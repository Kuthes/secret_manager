import json

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.api.deps import get_current_org, require_permission
from apps.api.app.api.loaders import get_owned_environment, get_owned_integration
from apps.api.app.core.crypto import crypto_engine
from apps.api.app.db.session import get_db
from apps.api.app.models.integration import (
    IntegrationConnection,
    SecretSync,
)
from apps.api.app.models.user import Organization
from apps.api.app.schemas.integration import (
    IntegrationCreate,
    IntegrationResponse,
    SyncCreate,
    SyncResponse,
)

router = APIRouter(prefix="/integrations", tags=["Integrations & Syncs"])


@router.get("", response_model=list[IntegrationResponse], dependencies=[Depends(require_permission("integration:list"))])
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = select(IntegrationConnection).where(IntegrationConnection.organization_id == org.id)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("integration:create"))])
async def create_integration(
    req: IntegrationCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    # Envelope-encrypt credentials before storage
    raw_creds = json.dumps(req.credentials)
    enc = crypto_engine.encrypt_secret(
        plaintext=raw_creds,
        org_id=str(org.id),
        project_id="integration",
        environment_id="integration",
        secret_key=req.name,
        version=1,
    )

    conn = IntegrationConnection(
        organization_id=org.id,
        name=req.name,
        provider_type=req.provider_type,
        credentials_encrypted=json.dumps(enc),
        status="healthy",
    )
    db.add(conn)
    await db.flush()
    return conn


@router.get("/syncs", response_model=list[SyncResponse], dependencies=[Depends(require_permission("integration:list"))])
async def list_syncs(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = select(SecretSync).join(IntegrationConnection).where(IntegrationConnection.organization_id == org.id)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/syncs", response_model=SyncResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("integration:create"))])
async def create_sync(
    req: SyncCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    # Verify connection belongs to org
    conn = await get_owned_integration(db=db, connection_id=req.connection_id, organization_id=org.id)

    # Verify project and environment belong to org
    await get_owned_environment(
        db=db,
        environment_id=req.environment_id,
        project_id=req.project_id,
        organization_id=org.id,
    )

    sync = SecretSync(
        project_id=req.project_id,
        environment_id=req.environment_id,
        connection_id=conn.id,
        target_path=req.target_path,
        sync_status="active",
    )
    db.add(sync)
    await db.flush()
    return sync
