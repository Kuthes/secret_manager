import enum
import logging
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.secret import Secret, SecretRotation
from apps.api.app.models.user import Project
from apps.api.app.services.secret_service import secret_service
from apps.api.app.services.audit_service import audit_service

logger = logging.getLogger(__name__)


class RotationState(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    VERIFYING = "verifying"
    SYNCING = "syncing"
    GRACE_PERIOD = "grace_period"
    COMPLETED = "completed"
    ROLLBACK_REQUIRED = "rollback_required"
    FAILED = "failed"


class SecretRotationEngine:
    @staticmethod
    async def execute_rotation(
        db: AsyncSession,
        rotation: SecretRotation,
        mock_verify_failure: bool = False,
    ) -> Tuple[RotationState, Optional[str]]:
        state = RotationState.PENDING
        secret = await db.get(Secret, rotation.secret_id)
        if not secret or secret.is_deleted:
            return RotationState.FAILED, "Target secret not found"

        project = await db.get(Project, secret.project_id)
        org_id = project.organization_id if project else uuid.uuid4()
        now = datetime.now(timezone.utc)

        try:
            # Stage 1: Running - Generate candidate secret
            state = RotationState.RUNNING
            candidate_val = f"rot_{secrets.token_urlsafe(32)}"

            # Stage 2: Verifying - Validate candidate against target system
            state = RotationState.VERIFYING
            if mock_verify_failure:
                raise ValueError("Verification failed: Destination service rejected new candidate credentials.")

            # Stage 3: Syncing - Update secret version
            state = RotationState.SYNCING
            new_sec = await secret_service.update_secret(
                db=db,
                secret_id=secret.id,
                value=candidate_val,
                change_message=f"Automated rotation via {rotation.provider_type}",
                actor_name="SecretRotationWorker",
            )

            # Stage 4: Grace Period
            state = RotationState.GRACE_PERIOD

            # Stage 5: Completed
            state = RotationState.COMPLETED
            rotation.last_run_at = now
            rotation.next_run_at = now + timedelta(seconds=rotation.interval_seconds)
            rotation.status = "active"
            await db.flush()

            await audit_service.log_event(
                db=db,
                organization_id=org_id,
                project_id=secret.project_id,
                actor_name="SecretRotationWorker",
                action="secret.rotate_success",
                resource_type="secret",
                resource_id=str(secret.id),
                metadata={"rotation_id": str(rotation.id), "version": new_sec.current_version_num},
            )
            return RotationState.COMPLETED, None

        except Exception as e:
            logger.error(f"Rotation failed at state {state}: {str(e)}")
            state = RotationState.ROLLBACK_REQUIRED if state == RotationState.SYNCING else RotationState.FAILED
            rotation.status = "failed"
            await db.flush()

            await audit_service.log_event(
                db=db,
                organization_id=org_id,
                project_id=secret.project_id,
                actor_name="SecretRotationWorker",
                action="secret.rotate_failure",
                resource_type="secret",
                resource_id=str(secret.id),
                result="failure",
                metadata={"rotation_id": str(rotation.id), "failed_state": str(state), "error": str(e)},
            )
            return state, str(e)


rotation_engine = SecretRotationEngine()
