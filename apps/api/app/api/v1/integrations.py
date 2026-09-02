import json
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db
from apps.api.app.models.integration import IntegrationConnection, SecretSync, SecretSyncRun
from apps.api.app.models.user import Organization, Project
from apps.api.app.schemas.integration import IntegrationCreate, IntegrationResponse, SyncCreate, SyncResponse
from apps.api.app.core.crypto import crypto_engine
from apps.api.app.api.deps import get_current_org, require_permission

router = APIRouter(prefix="/integrations", tags=["Integrations & Syncs"])


@router.get("", response_model=List[IntegrationResponse], dependencies=[Depends(require_permission("integration:list"))])
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


@router.get("/syncs", response_model=List[SyncResponse], dependencies=[Depends(require_permission("integration:list"))])
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
    conn = await db.get(IntegrationConnection, req.connection_id)
    if not conn or conn.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration connection not found")

    # Verify project belongs to org
    project = await db.get(Project, req.project_id)
    if not project or project.is_deleted or project.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    sync = SecretSync(
        project_id=req.project_id,
        environment_id=req.environment_id,
        connection_id=req.connection_id,
        target_path=req.target_path,
        sync_status="active",
    )
    db.add(sync)
    await db.flush()
    return sync
