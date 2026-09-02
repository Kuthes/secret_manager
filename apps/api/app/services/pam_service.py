import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from apps.api.app.models.pam import AccessResource, AccessRequest, AccessApproval
from apps.api.app.services.audit_service import audit_service


class PAMService:
    @staticmethod
    async def create_request(
        db: AsyncSession,
        resource_id: uuid.UUID,
        requester_id: uuid.UUID,
        requester_name: str,
        justification: str,
        duration_seconds: int,
    ) -> AccessRequest:
        resource = await db.get(AccessResource, resource_id)
        if not resource:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protected resource not found")

        clamped_duration = min(duration_seconds, resource.max_duration_seconds)

        req = AccessRequest(
            resource_id=resource.id,
            requester_id=requester_id,
            justification=justification,
            duration_seconds=clamped_duration,
            status="pending",
        )
        db.add(req)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=resource.organization_id,
            project_id=resource.project_id,
            actor_id=requester_id,
            actor_name=requester_name,
            action="access.request",
            resource_type="access_request",
            resource_id=str(req.id),
            metadata={"resource_name": resource.name, "duration_seconds": clamped_duration, "justification": justification},
        )

        return req

    @staticmethod
    async def review_request(
        db: AsyncSession,
        request_id: uuid.UUID,
        approver_id: uuid.UUID,
        approver_name: str,
        decision: str,
        comment: Optional[str] = None,
    ) -> AccessRequest:
        req = await db.get(AccessRequest, request_id)
        if not req or req.status != "pending":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Pending access request not found")

        # Phase 7.14: Self-Approval Protection
        if req.requester_id == approver_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Self-approval forbidden: Requesters cannot approve their own PAM access requests.",
            )

        resource = await db.get(AccessResource, req.resource_id)

        now = datetime.now(timezone.utc)
        if decision == "approved":
            req.status = "approved"
            req.expires_at = now + timedelta(seconds=req.duration_seconds)
        else:
            req.status = "rejected"

        approval = AccessApproval(
            request_id=req.id,
            approver_id=approver_id,
            decision=decision,
            comment=comment,
        )
        db.add(approval)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=resource.organization_id if resource else uuid.uuid4(),
            project_id=resource.project_id if resource else None,
            actor_id=approver_id,
            actor_name=approver_name,
            action=f"access.{decision}",
            resource_type="access_request",
            resource_id=str(req.id),
            metadata={"decision": decision, "comment": comment, "expires_at": req.expires_at.isoformat() if req.expires_at else None},
        )

        return req

    @staticmethod
    async def revoke_request(
        db: AsyncSession,
        request_id: uuid.UUID,
        actor_id: uuid.UUID,
        actor_name: str,
        reason: Optional[str] = None,
    ) -> AccessRequest:
        req = await db.get(AccessRequest, request_id)
        if not req:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found")

        resource = await db.get(AccessResource, req.resource_id)

        req.status = "revoked"
        req.revoked_at = datetime.now(timezone.utc)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=resource.organization_id if resource else uuid.uuid4(),
            project_id=resource.project_id if resource else None,
            actor_id=actor_id,
            actor_name=actor_name,
            action="access.revoke",
            resource_type="access_request",
            resource_id=str(req.id),
            metadata={"reason": reason or "Manual revocation"},
        )

        return req


pam_service = PAMService()
