import asyncio
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, and_

from apps.worker.celery_app import celery_app
from apps.api.app.db.session import async_session_factory
from apps.api.app.models.secret import SecretRotation, Secret
from apps.api.app.models.dynamic_secret import DynamicCredentialLease
from apps.api.app.models.pki import Certificate
from apps.api.app.models.notification import Notification
from apps.api.app.services.rotation_service import rotation_engine
from apps.api.app.services.audit_service import audit_service

logger = logging.getLogger(__name__)


@celery_app.task(name="apps.worker.tasks.rotate_scheduled_secrets")
def rotate_scheduled_secrets():
    async def _run():
        async with async_session_factory() as db:
            now = datetime.now(timezone.utc)
            stmt = select(SecretRotation).where(
                and_(SecretRotation.status == "active", SecretRotation.next_run_at <= now)
            )
            res = await db.execute(stmt)
            rotations = res.scalars().all()

            for rot in rotations:
                state, err = await rotation_engine.execute_rotation(db=db, rotation=rot)
                if err:
                    logger.warning(f"Rotation for secret {rot.secret_id} failed: {err}")
            await db.commit()

    asyncio.run(_run())


@celery_app.task(name="apps.worker.tasks.revoke_expired_leases")
def revoke_expired_leases():
    async def _run():
        async with async_session_factory() as db:
            now = datetime.now(timezone.utc)
            stmt = select(DynamicCredentialLease).where(
                and_(DynamicCredentialLease.status == "active", DynamicCredentialLease.expires_at <= now)
            )
            res = await db.execute(stmt)
            expired_leases = res.scalars().all()

            for lease in expired_leases:
                lease.status = "expired"
                lease.revoked_at = now
                await audit_service.log_event(
                    db=db,
                    organization_id=lease.provider.project.organization_id if (lease.provider and lease.provider.project) else None,
                    actor_name="LeaseReconciliationWorker",
                    action="dynamic.lease_expired",
                    resource_type="dynamic_lease",
                    resource_id=str(lease.id),
                    metadata={"issued_identity": lease.issued_identity},
                )
            await db.commit()

    asyncio.run(_run())


@celery_app.task(name="apps.worker.tasks.monitor_certificate_expiry")
def monitor_certificate_expiry():
    async def _run():
        async with async_session_factory() as db:
            now = datetime.now(timezone.utc)
            warning_window = now + timedelta(days=30)
            stmt = select(Certificate).where(
                and_(Certificate.status == "active", Certificate.valid_to <= warning_window)
            )
            res = await db.execute(stmt)
            expiring_certs = res.scalars().all()

            for cert in expiring_certs:
                if cert.ca and cert.ca.organization and cert.ca.organization.memberships:
                    notif = Notification(
                        user_id=cert.ca.organization.memberships[0].user_id,
                        organization_id=cert.ca.organization_id,
                        title=f"Certificate Expiring Soon: {cert.common_name}",
                        message=f"Certificate for {cert.common_name} (serial {cert.serial_number}) expires at {cert.valid_to.isoformat() if cert.valid_to else 'N/A'}.",
                        severity="warning",
                    )
                    db.add(notif)
            await db.commit()

    asyncio.run(_run())
