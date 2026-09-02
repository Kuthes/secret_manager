# AegisVault Disaster Recovery (DR) Plan

## 1. Objectives & Metrics
- **Recovery Point Objective (RPO)**: < 15 minutes (via PostgreSQL continuous WAL archiving).
- **Recovery Time Objective (RTO)**: < 30 minutes (automated containerized failover).

---

## 2. Disaster Recovery Tiers

| Tier | Failure Scenario | Automated Mitigation | Manual Intervention |
|------|------------------|----------------------|---------------------|
| Tier 1 | Single Container Crash | Docker / K8s restart policy | None |
| Tier 2 | Primary Database Node Outage | PostgreSQL replica promotion | DNS endpoint switch |
| Tier 3 | Regional Cloud Outage | Multi-region KMS + Replica failover | Update ingress routing |

---

## 3. Secret Zeroization & Recovery Verification
Post-recovery validation checklist:
1. `GET /api/v1/health` returns status `healthy`.
2. `POST /api/v1/audit/verify` confirms audit hash chain continuity.
3. Test secret retrieval to verify KMS MEK availability.
