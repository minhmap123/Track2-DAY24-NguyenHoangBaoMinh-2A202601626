"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w-])")
_BANK_RE = re.compile(
    r"(?i)(?:\bstk\b|s(?:ố|o)\s*t(?:à|a)i\s*kho(?:ả|a)n)\s*[:#-]?\s*(\d{8,16})(?!\d)"
)
_CCCD_LABEL_RE = re.compile(
    r"(?i)(?:\bcccd\b|c(?:ă|a)n\s*c(?:ư|u)(?:ớ|o)c)\D{0,20}(\d{12})(?!\d)"
)
_TWELVE_DIGIT_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)(0\d(?:[ .-]?\d){8,9})(?!\d)")


def _span(match: re.Match[str], entity_type: str, group: int = 0) -> dict:
    return {"type": entity_type, "start": match.start(group), "end": match.end(group)}


def detect(text: str) -> list[dict]:
    """Return deterministic regex matches with offsets into the original text.

    Account numbers are recognised from their banking label before generic
    12-digit IDs, preventing an STK with 12 digits from being mislabeled CCCD.
    """
    entities: list[dict] = []
    occupied: list[tuple[int, int]] = []

    def add(match: re.Match[str], entity_type: str, group: int = 0) -> None:
        start, end = match.span(group)
        if start == -1 or any(start < other_end and other_start < end for other_start, other_end in occupied):
            return
        entities.append(_span(match, entity_type, group))
        occupied.append((start, end))

    for match in _EMAIL_RE.finditer(text):
        add(match, "EMAIL")
    for match in _BANK_RE.finditer(text):
        add(match, "VN_BANK_ACCOUNT", 1)
    for match in _CCCD_LABEL_RE.finditer(text):
        add(match, "VN_CCCD", 1)
    for match in _TWELVE_DIGIT_RE.finditer(text):
        add(match, "VN_CCCD", 1)
    for match in _PHONE_RE.finditer(text):
        add(match, "VN_PHONE", 1)

    return sorted(entities, key=lambda entity: (entity["start"], entity["end"], entity["type"]))


def redact(text: str) -> str:
    redacted = text
    # Right-to-left replacement preserves offsets obtained from the original.
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[: entity["start"]] + replacement + redacted[entity["end"] :]
    return redacted
