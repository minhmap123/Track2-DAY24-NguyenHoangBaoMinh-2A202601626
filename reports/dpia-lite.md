# DPIA-lite (1 trang)

## 1. Dữ liệu gì

`search_docs` đọc ticket từ `corpus/`, là nội dung không tin cậy và có thể
chứa thông tin khách hàng hoặc prompt injection. `read_customer` có thể đọc
tên, CCCD, SĐT, số tài khoản, email và `related_tickets` từ
`data/customers.json`. Đây là dữ liệu synthetic của lab, không phải dữ liệu
cá nhân thật.

Trước khi đưa văn bản ticket sang bước tóm tắt, `agent.pii.redact()` thay các
entity nhận diện được bằng nhãn redaction. Ledger chỉ giữ hash của arguments,
classification, decision và reason; không giữ body của customer record.

## 2. Mục đích gì

Mục đích là tổng hợp ticket hỗ trợ và, khi cần cho ticket hợp lệ, tra customer
được liên kết với ticket đó. Run A chỉ tìm ticket; Run B chỉ nhận ticket ID
từ tên file và map sang customer bằng `related_tickets` trong nguồn tin cậy.
Customer ID do nội dung ticket tự do nêu ra không được dùng để đọc dữ liệu.

## 3. Chảy đi đâu

Trong đường chạy đã dùng để nộp bài (`--mock`), không có model provider hay
network egress: mock chạy local. Sink chỉ là `localhost:9999` của lab và
egress với dữ liệu restricted bị policy deny trước khi POST. Evidence của
replay là `reports/attack-after.log` và `reports/ledger.jsonl`.

Nếu chạy tuỳ chọn `--model claude-...`, ticket sau PII redaction được gửi tới
API của model provider bởi `agent.llm.RealLLM`; đó phải được ghi nhận như một
luồng dữ liệu xuyên biên giới, có hồ sơ/chấp thuận phù hợp trước khi dùng dữ
liệu thật. Đường này không được dùng trong evidence hoặc chấm điểm hiện tại.
