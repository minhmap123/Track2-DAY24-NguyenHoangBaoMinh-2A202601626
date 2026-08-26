"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

_TICKET_ID_RE = re.compile(r"^ticket-(\d+)\.md$")
_ALLOWED_EGRESS = ("localhost", 9999)


def _args_hash(args: object) -> str:
    encoded = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _trusted_customers_for_tickets(ticket_ids: set[int]) -> list[str]:
    """Map file-derived ticket IDs to customers using only the trusted store."""
    records = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return [
        str(record["customer_id"])
        for record in records
        if ticket_ids.intersection({int(ticket) for ticket in record.get("related_tickets", [])})
    ]


def _is_allowlisted(url: str) -> bool:
    parsed = urlparse(url)
    return (parsed.hostname, parsed.port) == _ALLOWED_EGRESS


def _record_decision(
    ledger_path: Path, run_id: str, tool: str, args: object, classification: str,
    allow: bool, reason: str, agent_owner: str, expires_at: str,
) -> None:
    ledger.append(
        {
            "ts": datetime.now(UTC).isoformat(),
            "agent_id": "lab24-governed-agent",
            "agent_owner": agent_owner,
            "run_id": run_id,
            "expires_at": expires_at,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": classification,
            "decision": "allow" if allow else "deny",
            "reason": reason or "deny: policy returned no reason",
        },
        ledger_path,
    )


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Execute separate untrusted and private-data runs with a PEP on each tool."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir is not None else DEFAULT_LEDGER_PATH
    started_at = datetime.now(UTC)
    run_id = hashlib.sha256(f"{started_at.isoformat()}:{message}".encode()).hexdigest()[:16]
    expires_at = (started_at + timedelta(minutes=5)).isoformat()

    # Run A: it may read only untrusted documents, never private data or egress.
    search_context = policy.PolicyContext("internal", "summarize-tickets", "run-a", 0, False)
    allow, reason = policy.check(search_context)
    _record_decision(
        ledger_path, run_id, "search_docs", {"query": message}, "internal", allow, reason, "run-a", expires_at
    )
    if not allow:
        return "Yêu cầu bị chặn bởi policy trước khi tìm ticket."
    raw_docs = tools.search_docs(message)

    # Only typed identifiers extracted from filenames cross the A/B boundary.
    ticket_ids = {
        int(match.group(1))
        for document in raw_docs
        if (match := _TICKET_ID_RE.match(str(document["id"])))
    }
    safe_docs = [{"id": doc["id"], "text": pii.redact(str(doc["text"]))} for doc in raw_docs]
    injected = llm.find_injection("\n\n".join(doc["text"] for doc in safe_docs))

    # Run B: customer IDs are obtained exclusively from related_tickets, never lure text.
    for customer_id in _trusted_customers_for_tickets(ticket_ids):
        read_context = policy.PolicyContext("restricted", "ticket-reconciliation", "run-b", 1, False)
        allow, reason = policy.check(read_context)
        _record_decision(
            ledger_path, run_id, "read_customer", {"customer_id": customer_id}, "restricted", allow, reason, "run-b", expires_at
        )
        if allow:
            tools.read_customer(customer_id)

    # An injection may request egress, but the PEP blocks restricted data before any POST.
    if injected is not None:
        target_url = injected.target_url
        if not _is_allowlisted(target_url):
            allow, reason = False, "deny: egress URL is not on the runner allowlist"
        else:
            egress_context = policy.PolicyContext("restricted", "injection-request", "run-b", 1, True)
            allow, reason = policy.check(egress_context)
        _record_decision(
            ledger_path, run_id, "http_post", {"url": target_url}, "restricted", allow, reason, "run-b", expires_at
        )
        if allow:
            # This branch is deliberately unreachable under the mandatory restricted-egress rule.
            tools.http_post(target_url, {"records": []})

    return llm.summarize(safe_docs)
