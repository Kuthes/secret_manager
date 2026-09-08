import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.api.deps import get_current_org, get_current_user, require_permission
from apps.api.app.api.loaders import (
    get_owned_dynamic_lease,
    get_owned_dynamic_provider,
    get_owned_environment,
)
from apps.api.app.core.crypto import crypto_engine
from apps.api.app.core.dynamic_engines import get_dynamic_engine
from apps.api.app.db.session import get_db
from apps.api.app.models.dynamic_secret import (
    DynamicCredentialLease,
    DynamicSecretProvider,
)
from apps.api.app.models.user import Organization, Project, User
from apps.api.app.schemas.dynamic import (
    DynamicProviderCreate,
    DynamicProviderResponse,
    LeaseIssueRequest,
    LeaseResponse,
)

router = APIRouter(prefix="/dynamic", tags=["Dynamic Secrets"])


@router.get("/providers", response_model=list[DynamicProviderResponse], dependencies=[Depends(require_permission("dynamic:list"))])
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
    # Validate provider type with engine registry
    get_dynamic_engine(req.provider_type)

    # Verify environment belongs to project and organization
    await get_owned_environment(
        db=db,
        environment_id=req.environment_id,
        project_id=req.project_id,
        organization_id=org.id,
    )

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
    provider = await get_owned_dynamic_provider(db=db, provider_id=provider_id, organization_id=org.id)
    if not provider.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dynamic provider not found or inactive")

    engine = get_dynamic_engine(provider.provider_type)

    ttl = req.ttl_seconds or provider.default_ttl_seconds
    ttl = min(ttl, provider.max_ttl_seconds)

    # Decrypt provider config for engine execution
    raw_config = {}
    try:
        enc_data = json.loads(provider.config_encrypted)
        decrypted_json = crypto_engine.decrypt_secret(
            encrypted_payload=enc_data,
            org_id=str(org.id),
            project_id=str(provider.project_id),
            environment_id=str(provider.environment_id),
            secret_key=provider.name,
            version=1,
        )
        raw_config = json.loads(decrypted_json)
    except Exception:
        raw_config = {}

    credentials, meta = engine.generate_credentials(raw_config, ttl)
    username = credentials.get("username", f"aegis_tmp_{secrets.token_hex(4)}")
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl)

    enc = crypto_engine.encrypt_secret(
        plaintext=json.dumps({"credentials": credentials, "metadata": meta}),
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
    lease = await get_owned_dynamic_lease(db=db, lease_id=lease_id, organization_id=org.id)

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
