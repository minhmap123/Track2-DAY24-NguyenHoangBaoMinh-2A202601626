# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement delete cascade; đây là stretch goal, không tuyên bố đã đáp ứng. | `Guide.md` § Stretch goals, mục 3 |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory nêu rõ đường `--mock` local và đường tuỳ chọn model provider cần hồ sơ trước khi dùng dữ liệu thật. | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | Policy context tách owner Run A/Run B, phân loại dữ liệu và chặn egress restricted; ledger gắn `agent_id`, `agent_owner`, `run_id` và TTL `expires_at` cho từng action. | `agent/runner.py:99`, `agent/runner.py:118`, `agent/policy.py:39`, `reports/ledger.jsonl` |
| ASI01 — goal hijack | Trifecta split chỉ chuyển ticket ID từ filename sang Run B; customer ID từ free text không quyết định `read_customer`. | `agent/runner.py:124`, `agent/runner.py:133`, `reports/attack-after.log` |
| ISO 42001 Clause 5-6 | Policy-as-code có reason bắt buộc và history review riêng theo commit. | `agent/policy.py:39`, git commits `039bfb4`, `11886eb` |
