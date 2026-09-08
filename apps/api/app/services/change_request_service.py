import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.crypto import crypto_engine
from apps.api.app.models.change_request import SecretChangeRequest
from apps.api.app.models.secret import Secret
from apps.api.app.models.user import Environment, Project
from apps.api.app.schemas.change_request import ChangeRequestCreate, ChangeRequestReview
from apps.api.app.services.audit_service import audit_service
from apps.api.app.services.secret_service import secret_service


class ChangeRequestService:
    @staticmethod
    async def create_change_request(
        db: AsyncSession,
        org_id: uuid.UUID,
        req: ChangeRequestCreate,
        actor_id: uuid.UUID,
        actor_name: str,
    ) -> SecretChangeRequest:
        """Create a new secret change request requiring dual-authorization review."""
        # 1. Verify Project and Environment belong to current Organization
        stmt_proj = select(Project).where(
            and_(
                Project.id == req.project_id,
                Project.organization_id == org_id,
            )
        )
        res_proj = await db.execute(stmt_proj)
        proj = res_proj.scalar_one_or_none()
        if not proj:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found in organization")

        stmt_env = select(Environment).where(
            and_(
                Environment.id == req.environment_id,
                Environment.project_id == req.project_id,
            )
        )
        res_env = await db.execute(stmt_env)
        env = res_env.scalar_one_or_none()
        if not env:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found in project")

        # 2. If secret_id provided, verify secret exists and matches scope
        normalized_key = req.proposed_key.strip().upper()
        if req.secret_id:
            stmt_sec = select(Secret).where(
                and_(
                    Secret.id == req.secret_id,
                    Secret.project_id == req.project_id,
                    Secret.environment_id == req.environment_id,
                    Secret.is_deleted.is_(False),
                )
            )
            res_sec = await db.execute(stmt_sec)
            sec = res_sec.scalar_one_or_none()
            if not sec:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found in scope")

        # 3. Encrypt proposed value using envelope encryption if provided
        encrypted_payload = None
        if req.proposed_value is not None:
            encrypted_payload = crypto_engine.encrypt_secret(
                plaintext=req.proposed_value,
                org_id=str(org_id),
                project_id=str(req.project_id),
                environment_id=str(req.environment_id),
                secret_key=normalized_key,
                version=1,
            )

        # 4. Create SecretChangeRequest entity
        cr = SecretChangeRequest(
            organization_id=org_id,
            project_id=req.project_id,
            environment_id=req.environment_id,
            secret_id=req.secret_id,
            change_type=req.change_type,
            title=req.title,
            description=req.description,
            proposed_key=normalized_key,
            proposed_payload=encrypted_payload,
            proposed_description=req.proposed_description,
            requester_id=actor_id,
            requester_name=actor_name,
            status="pending",
        )
        db.add(cr)
        await db.flush()

        # 5. Audit Log (committed atomically with change request)
        await audit_service.log_event(
            db=db,
            organization_id=org_id,
            project_id=req.project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="secret.change_request_created",
            resource_type="secret_change_request",
            resource_id=str(cr.id),
            metadata={
                "change_type": cr.change_type,
                "proposed_key": normalized_key,
                "secret_id": str(cr.secret_id) if cr.secret_id else None,
                "title": cr.title,
            },
        )

        await db.commit()
        await db.refresh(cr)
        return cr

    @staticmethod
    async def list_change_requests(
        db: AsyncSession,
        org_id: uuid.UUID,
        project_id: uuid.UUID | None = None,
        environment_id: uuid.UUID | None = None,
        status_filter: str | None = None,
    ) -> list[SecretChangeRequest]:
        """List change requests with multi-tenant filtering."""
        conditions = [SecretChangeRequest.organization_id == org_id]
        if project_id:
            conditions.append(SecretChangeRequest.project_id == project_id)
        if environment_id:
            conditions.append(SecretChangeRequest.environment_id == environment_id)
        if status_filter:
            conditions.append(SecretChangeRequest.status == status_filter)

        stmt = select(SecretChangeRequest).where(and_(*conditions)).order_by(desc(SecretChangeRequest.created_at))
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    async def get_change_request(
        db: AsyncSession,
        org_id: uuid.UUID,
        request_id: uuid.UUID,
    ) -> SecretChangeRequest:
        """Fetch a specific change request with tenant isolation."""
        stmt = select(SecretChangeRequest).where(
            and_(
                SecretChangeRequest.id == request_id,
                SecretChangeRequest.organization_id == org_id,
            )
        )
        res = await db.execute(stmt)
        cr = res.scalar_one_or_none()
        if not cr:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change request not found")
        return cr

    @staticmethod
    async def review_change_request(
        db: AsyncSession,
        org_id: uuid.UUID,
        request_id: uuid.UUID,
        review: ChangeRequestReview,
        actor_id: uuid.UUID,
        actor_name: str,
    ) -> SecretChangeRequest:
        """Review (approve/reject) a change request with strict four-eyes principle enforcement."""
        cr = await ChangeRequestService.get_change_request(db=db, org_id=org_id, request_id=request_id)

        if cr.status != "pending":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot review change request with status '{cr.status}'. Must be 'pending'.",
            )

        # Dual-authorization / Four-eyes enforcement: Requesters cannot approve their own requests
        if cr.requester_id == actor_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Self-approval is forbidden: Requesters cannot approve or reject their own change requests.",
            )

        cr.status = review.decision
        cr.reviewer_id = actor_id
        cr.reviewer_name = actor_name
        cr.review_comment = review.comment
        cr.reviewed_at = datetime.now(timezone.utc)

        await audit_service.log_event(
            db=db,
            organization_id=org_id,
            project_id=cr.project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action=f"secret.change_request_{review.decision}",
            resource_type="secret_change_request",
            resource_id=str(cr.id),
            metadata={
                "decision": review.decision,
                "comment": review.comment,
                "requester_id": str(cr.requester_id),
            },
        )

        await db.commit()
        await db.refresh(cr)
        return cr

    @staticmethod
    async def apply_change_request(
        db: AsyncSession,
        org_id: uuid.UUID,
        request_id: uuid.UUID,
        actor_id: uuid.UUID,
        actor_name: str,
    ) -> SecretChangeRequest:
        """Apply an approved change request to commit the secret mutation to the vault."""
        cr = await ChangeRequestService.get_change_request(db=db, org_id=org_id, request_id=request_id)

        if cr.status != "approved":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot apply change request with status '{cr.status}'. Must be 'approved'.",
            )

        # Decrypt candidate payload if present
        plain_val = None
        if cr.proposed_payload:
            plain_val = crypto_engine.decrypt_secret(
                encrypted_payload=cr.proposed_payload,
                org_id=str(org_id),
                project_id=str(cr.project_id),
                environment_id=str(cr.environment_id),
                secret_key=cr.proposed_key,
                version=1,
            )

        # Execute atomic secret mutation
        if cr.change_type == "create":
            if not plain_val:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing secret value for create action")
            secret = await secret_service.create_secret(
                db=db,
                project_id=cr.project_id,
                environment_id=cr.environment_id,
                key=cr.proposed_key,
                value=plain_val,
                comment=cr.proposed_description,
                actor_id=actor_id,
                actor_name=actor_name,
            )
            cr.secret_id = secret.id
        elif cr.change_type == "update":
            if not cr.secret_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing secret_id for update action")
            if not plain_val:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing proposed value for update action")
            await secret_service.update_secret(
                db=db,
                secret_id=cr.secret_id,
                value=plain_val,
                comment=cr.proposed_description,
                actor_id=actor_id,
                actor_name=actor_name,
            )
        elif cr.change_type == "delete":
            if not cr.secret_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing secret_id for delete action")
            await secret_service.delete_secret(
                db=db,
                secret_id=cr.secret_id,
                actor_id=actor_id,
                actor_name=actor_name,
            )

        cr.status = "applied"
        cr.applied_at = datetime.now(timezone.utc)

        await audit_service.log_event(
            db=db,
            organization_id=org_id,
            project_id=cr.project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="secret.change_request_applied",
            resource_type="secret_change_request",
            resource_id=str(cr.id),
            metadata={
                "change_type": cr.change_type,
                "secret_id": str(cr.secret_id) if cr.secret_id else None,
                "applied_by": actor_name,
            },
        )

        await db.commit()
        await db.refresh(cr)
        return cr

    @staticmethod
    async def cancel_change_request(
        db: AsyncSession,
        org_id: uuid.UUID,
        request_id: uuid.UUID,
        actor_id: uuid.UUID,
        actor_name: str,
    ) -> SecretChangeRequest:
        """Cancel a pending change request."""
        cr = await ChangeRequestService.get_change_request(db=db, org_id=org_id, request_id=request_id)

        if cr.status not in ["pending", "approved"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel change request with status '{cr.status}'.",
            )

        cr.status = "cancelled"

        await audit_service.log_event(
            db=db,
            organization_id=org_id,
            project_id=cr.project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="secret.change_request_cancelled",
            resource_type="secret_change_request",
            resource_id=str(cr.id),
            metadata={
                "cancelled_by": actor_name,
            },
        )

        await db.commit()
        await db.refresh(cr)
        return cr


change_request_service = ChangeRequestService()
