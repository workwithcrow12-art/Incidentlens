# Đối chiếu yêu cầu với mã nguồn và test

> Tài liệu lịch sử. Xem [README.md](../README.md#verification-and-remaining-limits) để biết kết quả kiểm chứng ngày 2026-11-16: 160 test qua trên SQLite/Windows, coverage 99%; PostgreSQL và Docker chưa được kiểm chứng lại. Các tuyên bố cũ bên dưới không phải kết quả của lần sửa hiện tại.

Tài liệu gốc: `ke-hoach-du-an-ai-dieu-tra-su-co.md`.

Ký hiệu: ✅ đã làm và có test · ⚠️ đã làm nhưng khác kế hoạch · ⬜ không thuộc phạm vi mã nguồn hoặc chưa làm.

## 1. Nguyên tắc thiết kế (mục 3)

| Nguyên tắc | | Kiểm chứng bằng test |
| :--- | :-: | :--- |
| Cảnh báo khẩn cấp không chờ AI | ✅ | `test_critical_pages_first_then_investigates`, `test_broken_investigation_never_blocks_paging`, `test_slow_investigation_is_cut_off` |
| AI gợi ý, con người quyết định | ✅ | `test_action_denied_cases`, `test_dry_run_by_default_does_not_execute`, `test_slack_buttons_require_valid_signature` |
| Mọi kết luận phải có bằng chứng | ✅ | `test_full_investigation_finds_deploy`, `test_no_evidence_means_no_hypothesis`, `test_llm_hallucinated_evidence_is_dropped`, `test_investigation_model_caps_hypotheses` |
| Dùng lại công cụ sẵn có | ✅ | Gom nhóm và khử trùng lặp cơ bản do Alertmanager làm (`config/alertmanager.example.yml`) |
| Giá trị phải đo được | ✅ | `test_roi_numbers`, `test_roi_with_measured_baseline` |

## 2. Phân loại và leo thang (mục 4)

| Yêu cầu | | Kiểm chứng |
| :--- | :-: | :--- |
| Ba mức 🔴🟡⚪ do luật quyết định | ✅ | `tests/test_routing.py` (9 test) |
| 🔴 gọi PagerDuty + Slack ngay | ✅ | `test_critical_pages_first_then_investigates`, `test_pagerduty_trigger_resolve_and_dry_run` |
| Gửi lại không gây spam | ✅ | `test_resend_does_not_spam_or_reinvestigate` |
| Leo thang khi kéo dài quá lâu | ✅ | `test_warning_is_not_paged_but_escalates_later`, `test_escalation_uses_real_start_time` |
| Leo thang khi lặp lại quá nhiều lần | ✅ | `test_escalation_after_too_many_repeats` |
| Leo thang khi vượt ngưỡng nặng hơn | ✅ | Viết thêm một luật cảnh báo mức critical trong Prometheus cho ngưỡng nặng hơn; nó sẽ đi thẳng vào luồng 🔴 |
| Leo thang khi nhiều 🟡 liên quan cùng xảy ra | ⬜ | Chưa làm. Dịch vụ phụ thuộc đang có cảnh báo hiện là bằng chứng điều tra, chưa phải luật leo thang |

## 3. Năm năng lực (mục 6)

| Năng lực | | Kiểm chứng |
| :--- | :-: | :--- |
| ① Điều tra: metric, log, deploy, phụ thuộc → 1–3 giả thuyết | ✅ | `tests/test_engine.py` (14 test), `tests/test_signals.py` |
| ① Kết quả trong 2–5 phút | ✅ | Giới hạn cứng 240 giây; thời gian thật được ghi trong mỗi cuộc điều tra |
| ① Trace của request chậm | ⬜ | Chưa làm (chưa nối Tempo/Jaeger) |
| ② Liên kết deploy | ✅ | `test_github_deployments`, `test_deploy_after_incident_is_not_blamed` |
| ② Thay đổi config, feature flag, Terraform | ⬜ | Chưa làm. Giao diện `ChangeProvider` cho phép thêm nguồn mới |
| ③ Trí nhớ sự cố | ⚠️ | `test_memory_of_past_incident`, `test_memory_prefers_incidents_with_known_cause`, `test_full_incident_lifecycle`. **Khác kế hoạch:** dùng điểm tương đồng có cấu trúc + từ ngữ thay cho pgvector (xem mục 7) |
| ④ Nút hành động, có người duyệt, có nhật ký | ✅ | `tests/test_memory_actions.py`, `test_executed_action_becomes_the_fix`, `test_slack_buttons_require_valid_signature` |
| ⑤ Báo cáo ROI tự động hằng tháng | ✅ | `tests/test_reports.py`, `test_maintenance_publishes_last_month_once_and_purges` |
| Bản nháp postmortem | ✅ | `test_full_incident_lifecycle`, `test_postmortem_for_unresolved_incident` |

## 4. Giới hạn của AI (mục 7)

| Yêu cầu | | Kiểm chứng |
| :--- | :-: | :--- |
| AI không quyết định việc gọi on-call | ✅ | Định tuyến nằm trong `routing/rules.py`, không gọi tới `investigation/` |
| AI không tự chạy lệnh | ✅ | `ActionRunner` chỉ được gọi từ `handle_interaction` (nút bấm Slack đã xác thực) |
| Không dùng % tin cậy do AI tự báo | ✅ | `test_confidence_rules`, `test_llm_rewrites_but_code_sets_confidence` |
| Vòng phản hồi 👍/👎 | ✅ | `test_feedback_down`, `test_full_incident_lifecycle`, `test_feedback_resolution_postmortem_and_roi` |
| LLM lỗi không làm hỏng hệ thống | ✅ | `test_llm_garbage_or_outage_falls_back_to_rules` |
| Chống prompt injection qua log | ✅ | `test_llm_never_receives_raw_secrets` (LLM chỉ nhận mô tả đã xử lý, không nhận log thô) |

## 5. Đầu ra (mục 8) và bảo mật (mục 10)

| Yêu cầu | | Kiểm chứng |
| :--- | :-: | :--- |
| Thẻ điều tra Slack có nút bấm | ✅ | `test_critical_pages_first_then_investigates`, `tests/test_edges.py` |
| Digest Markdown kèm giả thuyết | ✅ | `test_digest_with_hypothesis`, `test_digest_shows_escalation_and_recent_deploy` |
| Lưu Git (commit + push) | ✅ | `test_digest_is_committed_and_pushed` (push tới một remote thật trên đĩa) |
| Che dữ liệu nhạy cảm | ✅ | `tests/test_redact.py` (21 trường hợp) |
| Quyền tối thiểu (chỉ đọc) | ✅ | Client Prometheus/Loki/GitHub chỉ dùng lệnh GET |
| Audit log | ✅ | Bảng `action_log` + `investigations`; `test_full_incident_lifecycle` |
| Thời hạn xóa dữ liệu | ✅ | `IL_RETENTION_DAYS`; `test_maintenance_publishes_last_month_once_and_purges` |
| LLM tự host | ✅ | `OpenAICompatibleLLM`; `test_openai_compatible_client` |
| Chọn vùng lưu trữ, SOC 2, SSO | ⬜ | Việc của tổ chức và hạ tầng, không phải mã nguồn |

## 6. Việc còn lại của Giai đoạn 1

| Việc | | Kiểm chứng |
| :--- | :-: | :--- |
| Tự commit + push digest | ✅ | `test_digest_is_committed_and_pushed`, `test_git_push_failure_is_logged_not_raised` |
| Lưu thời điểm digest gần nhất vào CSDL | ✅ | `test_digest_window_survives_restart` |
| Dọn dữ liệu cũ | ✅ | `test_maintenance_publishes_last_month_once_and_purges` |
| Đo baseline | ✅ | Bảng `episodes` + `config/baseline.yaml` |
| Migration CSDL (Alembic) | ⬜ | Chưa làm. Bảng được tạo tự động lần đầu |

## 7. Những chỗ khác với kế hoạch

1. **Trí nhớ sự cố không dùng pgvector.** Dùng điểm tương đồng có cấu trúc (cùng loại cảnh báo, cùng dịch vụ) cộng độ trùng từ ngữ. Lý do: chạy được trên mọi CSDL, không cần mô hình embedding, kết quả giải thích được và test được. Với vài trăm sự cố mỗi công ty, cách này đủ dùng. Khi lên hàng nghìn sự cố có thể thay bằng tìm kiếm vector mà không đổi giao diện `IncidentMemory`.
2. **Điều tra hai lớp thay vì "agent tự gọi công cụ".** Mã cố định thu thập bằng chứng, luật tạo giả thuyết, LLM (nếu bật) chỉ viết lại. Lý do: kết quả lặp lại được, không phụ thuộc LLM để hoạt động, và LLM không thể bịa bằng chứng.
3. **Chỉ hỗ trợ Prometheus + Loki + GitHub + Alertmanager.** Datadog, CloudWatch, GitLab, ArgoCD, Opsgenie chưa có.
4. **Không đo MTTA.** Cần nhận webhook từ PagerDuty để biết lúc có người nhận. Báo cáo dùng MTTR.

## 8. Đã kiểm chứng gì và chưa kiểm chứng gì

**Đã kiểm chứng trong môi trường phát triển:**

- 115 test tự động qua trên cả SQLite và PostgreSQL 16 thật; độ phủ 99%.
- Server thật (uvicorn) khởi động từ file cấu hình, nhận cảnh báo, mở sự cố, tạo digest và báo cáo, tắt sạch.
- Mã gọi API (Prometheus, Loki, GitHub, Slack, PagerDuty, LLM) chạy qua HTTP giả lập đúng định dạng API công khai.
- Lệnh hành động chạy bằng tiến trình con thật; Git commit và push tới remote thật trên đĩa.

**Chưa kiểm chứng được, cần làm khi triển khai:**

- **Chưa chạy với hệ thống thật nào.** Các API bên ngoài được giả lập. Lần nối đầu tiên với Prometheus, Loki, Slack, PagerDuty thật có thể lộ ra khác biệt nhỏ. Đặc biệt: định dạng link Grafana Explore thay đổi theo phiên bản Grafana.
- **Chưa gọi LLM thật lần nào** (không có khóa API trong môi trường phát triển). Chất lượng câu chữ của LLM chưa được đánh giá.
- **Chưa build Docker image** (môi trường phát triển không có Docker).
- **Độ chính xác của giả thuyết trên sự cố thật là chưa biết.** Hệ thống đo được chỉ số này (nút ✅/👎 → báo cáo ROI), nhưng mục tiêu ≥60% chỉ kiểm chứng được qua pilot với sự cố thật. Các luật hiện tại bắt tốt ba kiểu: sự cố sau deploy, sự cố lan từ phụ thuộc, cạn tài nguyên. Các kiểu khác sẽ cần thêm luật hoặc dựa vào LLM.
- **Các câu truy vấn trong `config/signals.yaml` là mẫu** theo tên metric phổ biến. Phải sửa cho khớp hệ thống của bạn thì điều tra mới có bằng chứng.
- **Tính khả thi kinh doanh** (khách hàng có trả 100$/người/tháng hay không) không thể chứng minh bằng mã nguồn. Điều kiện qua cổng ở mục 12 của kế hoạch vẫn giữ nguyên.
