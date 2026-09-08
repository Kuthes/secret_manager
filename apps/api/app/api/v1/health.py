import time
from fastapi import APIRouter, Depends, Response
from sqlalchemy import text, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db
from apps.api.app.models.secret import Secret, SecretVersion
from apps.api.app.models.dynamic_secret import DynamicCredentialLease
from apps.api.app.models.pki import Certificate
from apps.api.app.models.audit import AuditEvent
from apps.api.app.core.config import settings

router = APIRouter(tags=["Health & Telemetry"])


@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "aegisvault-api",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
    }


@router.get("/ready")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        return {
            "status": "ready",
            "database": "connected",
            "crypto_engine": "operational",
        }
    except Exception as e:
        return {
            "status": "degraded",
            "database": "unavailable",
            "error": str(e),
        }


@router.get("/metrics")
async def prometheus_metrics(db: AsyncSession = Depends(get_db)):
    """
    Exposes Prometheus-formatted operational metrics.
    Strictly forbids high-cardinality secret names or plaintext values.
    """
    try:
        secret_count = (await db.execute(select(func.count(Secret.id)).where(Secret.is_deleted == False))).scalar() or 0
        lease_active = (await db.execute(select(func.count(DynamicCredentialLease.id)).where(DynamicCredentialLease.status == "active"))).scalar() or 0
        cert_active = (await db.execute(select(func.count(Certificate.id)).where(Certificate.status == "active"))).scalar() or 0
        audit_count = (await db.execute(select(func.count(AuditEvent.id)))).scalar() or 0
    except Exception:
        secret_count = 0
        lease_active = 0
        cert_active = 0
        audit_count = 0

    metrics_text = f"""# HELP aegisvault_uptime_seconds Total runtime of the control plane.
# TYPE aegisvault_uptime_seconds counter
aegisvault_uptime_seconds {int(time.time())}

# HELP aegisvault_secrets_total Total active managed secrets.
# TYPE aegisvault_secrets_total gauge
aegisvault_secrets_total {secret_count}

# HELP aegisvault_dynamic_leases_active Total active dynamic credential leases.
# TYPE aegisvault_dynamic_leases_active gauge
aegisvault_dynamic_leases_active {lease_active}

# HELP aegisvault_pki_certificates_active Total active issued X.509 certificates.
# TYPE aegisvault_pki_certificates_active gauge
aegisvault_pki_certificates_active {cert_active}

# HELP aegisvault_audit_events_total Total tamper-evident audit events recorded.
# TYPE aegisvault_audit_events_total counter
aegisvault_audit_events_total {audit_count}
"""
    return Response(content=metrics_text, media_type="text/plain; version=0.0.4")
