import json
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db
from apps.api.app.models.dynamic_secret import DynamicSecretProvider, DynamicCredentialLease
from apps.api.app.models.user import Project, Organization, User
from apps.api.app.schemas.dynamic import (
    DynamicProviderCreate,
    DynamicProviderResponse,
    LeaseIssueRequest,
    LeaseResponse,
)
from apps.api.app.core.crypto import crypto_engine
from apps.api.app.api.deps import get_current_user, get_current_org, require_permission

router = APIRouter(prefix="/dynamic", tags=["Dynamic Secrets"])


@router.get("/providers", response_model=List[DynamicProviderResponse], dependencies=[Depends(require_permission("dynamic:list"))])
async def list_providers(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = select(DynamicSecretProvider).join(Project).where(Project.organization_id == org.id)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/providers", response_model=DynamicProviderResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("dynamic:create"))])
async def create_provider(
    req: DynamicProviderCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    project = await db.get(Project, req.project_id)
    if not project or project.is_deleted or project.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    enc = crypto_engine.encrypt_secret(
        plaintext=json.dumps(req.config),
        org_id=str(org.id),
        project_id=str(req.project_id),
        environment_id=str(req.environment_id),
        secret_key=req.name,
        version=1,
    )
    provider = DynamicSecretProvider(
        project_id=req.project_id,
        environment_id=req.environment_id,
        name=req.name,
        provider_type=req.provider_type,
        default_ttl_seconds=req.default_ttl_seconds,
        max_ttl_seconds=req.max_ttl_seconds,
        config_encrypted=json.dumps(enc),
    )
    db.add(provider)
    await db.flush()
    return provider


@router.post("/providers/{provider_id}/issue", response_model=LeaseResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("dynamic:issue"))])
async def issue_lease(
    provider_id: uuid.UUID,
    req: LeaseIssueRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    provider = await db.get(DynamicSecretProvider, provider_id)
    if not provider or not provider.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dynamic provider not found or inactive")

    project = await db.get(Project, provider.project_id)
    if not project or project.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dynamic provider not found or inactive")

    ttl = req.ttl_seconds or provider.default_ttl_seconds
    ttl = min(ttl, provider.max_ttl_seconds)

    # Generate ephemeral credential identity
    suffix = secrets.token_hex(4)
    username = f"aegis_tmp_{suffix}"
    password = f"P_{secrets.token_urlsafe(16)}"
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl)

    credentials = {"username": username, "password": password}
    enc = crypto_engine.encrypt_secret(
        plaintext=json.dumps(credentials),
        org_id=str(org.id),
        project_id=str(provider.project_id),
        environment_id=str(provider.environment_id),
        secret_key=username,
        version=1,
    )

    lease = DynamicCredentialLease(
        provider_id=provider.id,
        issued_identity=username,
        credential_encrypted=json.dumps(enc),
        ttl_seconds=ttl,
        expires_at=expires,
        status="active",
        requester_id=user.id,
    )
    db.add(lease)
    await db.flush()

    return LeaseResponse(
        id=lease.id,
        provider_id=lease.provider_id,
        issued_identity=lease.issued_identity,
        credentials=credentials,
        ttl_seconds=lease.ttl_seconds,
        expires_at=lease.expires_at,
        status=lease.status,
    )


@router.post("/leases/{lease_id}/revoke", response_model=LeaseResponse, dependencies=[Depends(require_permission("dynamic:revoke"))])
async def revoke_lease(
    lease_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    lease = await db.get(DynamicCredentialLease, lease_id)
    if not lease:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")

    provider = await db.get(DynamicSecretProvider, lease.provider_id)
    project = await db.get(Project, provider.project_id) if provider else None
    if not provider or not project or project.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")

    lease.status = "revoked"
    lease.revoked_at = datetime.now(timezone.utc)
    await db.flush()

    return LeaseResponse(
        id=lease.id,
        provider_id=lease.provider_id,
        issued_identity=lease.issued_identity,
        ttl_seconds=lease.ttl_seconds,
        expires_at=lease.expires_at,
        status=lease.status,
    )
