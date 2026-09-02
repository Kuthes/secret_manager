import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.db.session import get_db
from apps.api.app.models.pam import AccessResource, AccessRequest, AccessApproval
from apps.api.app.models.user import User, Organization
from apps.api.app.schemas.pam import (
    AccessResourceCreate,
    AccessResourceResponse,
    AccessRequestCreate,
    AccessRequestResponse,
    ApprovalRequest,
)
from apps.api.app.services.pam_service import pam_service
from apps.api.app.api.deps import get_current_user, get_current_org, require_permission

router = APIRouter(prefix="/access", tags=["Privileged Access"])


@router.get("/resources", response_model=List[AccessResourceResponse], dependencies=[Depends(require_permission("pam:list"))])
async def list_resources(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = select(AccessResource).where(AccessResource.organization_id == org.id)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/resources", response_model=AccessResourceResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("pam:admin"))])
async def create_resource(
    req: AccessResourceCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    resource = AccessResource(
        organization_id=org.id,
        name=req.name,
        resource_type=req.resource_type,
        resource_identifier=req.resource_identifier,
        max_duration_seconds=req.max_duration_seconds,
    )
    db.add(resource)
    await db.flush()
    return resource


@router.get("/requests", response_model=List[AccessRequestResponse], dependencies=[Depends(require_permission("pam:list"))])
async def list_requests(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = (
        select(AccessRequest)
        .join(AccessResource)
        .options(selectinload(AccessRequest.resource))
        .where(AccessResource.organization_id == org.id)
        .order_by(AccessRequest.created_at.desc())
    )
    res = await db.execute(stmt)
    reqs = res.scalars().all()

    output = []
    for r in reqs:
        requester = await db.get(User, r.requester_id) if r.requester_id else None
        output.append(
            AccessRequestResponse(
                id=r.id,
                resource_id=r.resource_id,
                resource_name=r.resource.name if r.resource else None,
                requester_id=r.requester_id,
                requester_name=requester.full_name if requester else "Unknown User",
                justification=r.justification,
                duration_seconds=r.duration_seconds,
                status=r.status,
                expires_at=r.expires_at,
                created_at=r.created_at,
            )
        )
    return output


@router.post("/requests", response_model=AccessRequestResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("pam:request"))])
async def create_request(
    req: AccessRequestCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    resource = await db.get(AccessResource, req.resource_id)
    if not resource or resource.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protected resource not found")

    access_req = await pam_service.create_request(
        db=db,
        resource_id=req.resource_id,
        requester_id=user.id,
        requester_name=user.full_name,
        justification=req.justification,
        duration_seconds=req.duration_seconds,
    )
    return AccessRequestResponse(
        id=access_req.id,
        resource_id=access_req.resource_id,
        resource_name=resource.name,
        requester_id=user.id,
        requester_name=user.full_name,
        justification=access_req.justification,
        duration_seconds=access_req.duration_seconds,
        status=access_req.status,
        expires_at=access_req.expires_at,
        created_at=access_req.created_at,
    )


@router.post("/requests/{request_id}/review", response_model=AccessRequestResponse, dependencies=[Depends(require_permission("pam:approve"))])
async def review_request(
    request_id: uuid.UUID,
    req: ApprovalRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    access_req = await db.get(AccessRequest, request_id)
    if not access_req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found")

    resource = await db.get(AccessResource, access_req.resource_id)
    if not resource or resource.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found")

    reviewed = await pam_service.review_request(
        db=db,
        request_id=request_id,
        approver_id=user.id,
        approver_name=user.full_name,
        decision=req.decision,
        comment=req.comment,
    )
    requester = await db.get(User, reviewed.requester_id) if reviewed.requester_id else None
    return AccessRequestResponse(
        id=reviewed.id,
        resource_id=reviewed.resource_id,
        resource_name=resource.name if resource else None,
        requester_id=reviewed.requester_id,
        requester_name=requester.full_name if requester else "Unknown User",
        justification=reviewed.justification,
        duration_seconds=reviewed.duration_seconds,
        status=reviewed.status,
        expires_at=reviewed.expires_at,
        created_at=reviewed.created_at,
    )


@router.post("/requests/{request_id}/revoke", response_model=AccessRequestResponse, dependencies=[Depends(require_permission("pam:revoke"))])
async def revoke_request(
    request_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    access_req = await db.get(AccessRequest, request_id)
    if not access_req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found")

    resource = await db.get(AccessResource, access_req.resource_id)
    if not resource or resource.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found")

    revoked = await pam_service.revoke_request(
        db=db,
        request_id=request_id,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    requester = await db.get(User, revoked.requester_id) if revoked.requester_id else None
    return AccessRequestResponse(
        id=revoked.id,
        resource_id=revoked.resource_id,
        resource_name=resource.name if resource else None,
        requester_id=revoked.requester_id,
        requester_name=requester.full_name if requester else "Unknown User",
        justification=revoked.justification,
        duration_seconds=revoked.duration_seconds,
        status=revoked.status,
        expires_at=revoked.expires_at,
        created_at=revoked.created_at,
    )
