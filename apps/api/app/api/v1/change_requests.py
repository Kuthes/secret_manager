import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.api.deps import (
    get_current_org,
    get_current_user,
    get_db,
    require_permission,
)
from apps.api.app.models.user import Organization, User
from apps.api.app.schemas.change_request import (
    ChangeRequestCreate,
    ChangeRequestResponse,
    ChangeRequestReview,
)
from apps.api.app.services.change_request_service import change_request_service

router = APIRouter(prefix="/change-requests", tags=["Secret Change Requests"])


@router.post("", response_model=ChangeRequestResponse, dependencies=[Depends(require_permission("secret:change_request_create"))])
async def create_change_request(
    req: ChangeRequestCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Submit a secret change request for dual-authorization approval."""
    return await change_request_service.create_change_request(
        db=db,
        org_id=org.id,
        req=req,
        actor_id=user.id,
        actor_name=user.full_name,
    )


@router.get("", response_model=list[ChangeRequestResponse], dependencies=[Depends(require_permission("secret:change_request_read"))])
async def list_change_requests(
    project_id: uuid.UUID | None = Query(None),
    environment_id: uuid.UUID | None = Query(None),
    status: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    """List secret change requests for the organization."""
    return await change_request_service.list_change_requests(
        db=db,
        org_id=org.id,
        project_id=project_id,
        environment_id=environment_id,
        status_filter=status,
    )


@router.get("/{request_id}", response_model=ChangeRequestResponse, dependencies=[Depends(require_permission("secret:change_request_read"))])
async def get_change_request(
    request_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    """Retrieve details of a secret change request."""
    return await change_request_service.get_change_request(
        db=db,
        org_id=org.id,
        request_id=request_id,
    )


@router.post("/{request_id}/review", response_model=ChangeRequestResponse, dependencies=[Depends(require_permission("secret:change_request_review"))])
async def review_change_request(
    request_id: uuid.UUID,
    review: ChangeRequestReview,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Review (approve or reject) a pending change request with four-eyes enforcement."""
    return await change_request_service.review_change_request(
        db=db,
        org_id=org.id,
        request_id=request_id,
        review=review,
        actor_id=user.id,
        actor_name=user.full_name,
    )


@router.post("/{request_id}/apply", response_model=ChangeRequestResponse, dependencies=[Depends(require_permission("secret:change_request_apply"))])
async def apply_change_request(
    request_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Apply an approved change request directly to the vault."""
    return await change_request_service.apply_change_request(
        db=db,
        org_id=org.id,
        request_id=request_id,
        actor_id=user.id,
        actor_name=user.full_name,
    )


@router.post("/{request_id}/cancel", response_model=ChangeRequestResponse, dependencies=[Depends(require_permission("secret:change_request_cancel"))])
async def cancel_change_request(
    request_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Cancel a pending secret change request."""
    return await change_request_service.cancel_change_request(
        db=db,
        org_id=org.id,
        request_id=request_id,
        actor_id=user.id,
        actor_name=user.full_name,
    )
