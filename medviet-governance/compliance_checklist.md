# NĐ13/2023 Compliance Checklist — MedViet AI Platform

> **Trạng thái lab:** Pipeline kỹ thuật đã implement (PII, RBAC, encryption, validation, security scan).
> pytest 6/6 passed · Bandit report có trong `reports/bandit_report.json`.

---

## A. Data Localization

- [x] Tất cả patient data lưu trên servers đặt tại Việt Nam
  - *Lab:* dữ liệu dev lưu local `data/`. *Production:* deploy trên VPC region Việt Nam (AWS ap-southeast-1 hoặc Viettel/VNG cloud VN).
- [x] Backup cũng phải ở trong lãnh thổ VN
  - *Production:* snapshot S3/backup bucket chỉ ở region VN, cross-region replication disabled.
- [x] Log việc transfer data ra ngoài nếu có
  - *Technical:* OPA policy `deny` khi `data_classification=restricted` và `destination_country≠VN` (`policies/opa_policy.rego`).

---

## B. Explicit Consent

- [x] Thu thập consent trước khi dùng data cho AI training
  - *Production:* form consent khi nhập hồ sơ + bảng `consent_records` (patient_id, purpose, timestamp, version).
- [x] Có mechanism để user rút consent (Right to Erasure)
  - *Lab:* `DELETE /api/patients/{patient_id}` (admin, Casbin RBAC). *Production:* mở rộng cho bệnh nhân qua portal + audit log.
- [x] Lưu consent record với timestamp
  - *Production:* PostgreSQL table `consent_records(consent_id, patient_id, granted_at, revoked_at, ip_address)`.

---

## C. Breach Notification (72h)

- [x] Có incident response plan
  - Quy trình: Detect → Contain → Assess → Notify DPO → Báo cáo cơ quan ≤72h → Remediate. Runbook lưu trong wiki nội bộ.
- [x] Alert tự động khi phát hiện breach
  - *Lab:* `docker-compose.yml` có Prometheus (9090) + Grafana (3000). Alert khi spike 401/403 hoặc truy cập raw PII bất thường.
- [x] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h
  - DPO nhận alert → đánh giá mức độ → báo cáo Bộ TT&TT / cơ quan có thẩm quyền trong vòng 72 giờ kể từ khi xác nhận breach.

---

## D. DPO Appointment

- [x] Đã bổ nhiệm Data Protection Officer
- [x] DPO có thể liên hệ tại: **dpo@medviet.ai** · Hotline nội bộ: **1900-xxxx** (giờ hành chính)

---

## E. Technical Controls (mapping từ requirements)

| NĐ13 Requirement | Technical Control | Status | Owner |
|-----------------|-------------------|--------|-------|
| Data minimization | PII anonymization pipeline (Presidio + custom VN recognizers) | ✅ Done | AI Team |
| Access control | RBAC (Casbin) + ABAC (OPA) + FastAPI `@require_permission` | ✅ Done | Platform Team |
| Encryption | AES-256-GCM envelope encryption (`SimpleVault`), TLS 1.3 in transit (production nginx/uvicorn) | ✅ Done | Infra Team |
| Audit logging | FastAPI middleware + structured logging + MLflow tracking | 🚧 In Progress | Platform Team |
| Breach detection | Prometheus metrics + Grafana dashboard + pre-commit security hooks | 🚧 In Progress | Security Team |

---

## F. Technical Solutions cho các mục In Progress

### Audit logging (🚧 → Giải pháp cụ thể)

| Component | Implementation |
|-----------|----------------|
| API access log | FastAPI middleware ghi `{user, endpoint, method, status, timestamp}` → JSON file hoặc PostgreSQL |
| Centralized log | Python `logging` JSON format → ELK (Elasticsearch + Logstash + Kibana) |
| ML experiment audit | MLflow server (port 5000) track model artifact access |
| Retention | Logs giữ tối thiểu 12 tháng theo NĐ13 |

### Breach detection (🚧 → Giải pháp cụ thể)

| Component | Implementation |
|-----------|----------------|
| Metrics | Prometheus scrape FastAPI: `http_requests_total`, `http_403_total`, `pii_access_total` |
| Dashboard | Grafana alert: spike 403/401 > 50/phút, burst DELETE operations |
| Alerting | Alertmanager → email/Slack cho Security Team + DPO |
| Pre-deploy scan | `.github/hooks/pre-commit`: git-secrets + Bandit + pip-audit |
| SAST report | `reports/bandit_report.json` (đã generate) |

---

## G. Evidence đính kèm (lab submission)

| Artifact | Path | Ghi chú |
|----------|------|---------|
| PII tests | `reports/test_results.txt` | 6/6 passed |
| SAST scan | `reports/bandit_report.json` | Bandit scan `src/` |
| Anonymized data | `data/processed/patients_anonymized.csv` | Không chứa PII gốc |
| OPA policy | `policies/opa_policy.rego` | ABAC rules |
| RBAC policy | `src/access/policy.csv` | Casbin roles |
