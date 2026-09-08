import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.api.deps import get_current_org, get_current_user, require_permission
from apps.api.app.api.loaders import (
    get_owned_environment,
    get_owned_secret,
)
from apps.api.app.core.rate_limiter import check_rate_limit
from apps.api.app.db.session import get_db
from apps.api.app.models.secret import Secret, SecretVersion
from apps.api.app.models.user import Organization, User
from apps.api.app.schemas.secret import (
    RollbackRequest,
    SecretCreate,
    SecretResponse,
    SecretRevealResponse,
    SecretUpdate,
    SecretVersionResponse,
)
from apps.api.app.services.audit_service import audit_service
from apps.api.app.services.secret_service import secret_service

router = APIRouter(prefix="/secrets", tags=["Secrets"])


@router.get("", response_model=list[SecretResponse], dependencies=[Depends(require_permission("secret:list"))])
async def list_secrets(
    project_id: uuid.UUID = Query(...),
    environment_id: uuid.UUID = Query(...),
    path: str = Query("/"),
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """List secrets for an environment. Note: Plaintext values are NEVER returned in list APIs."""
    # Strict tenant and project-environment relationship verification
    await get_owned_environment(db=db, environment_id=environment_id, project_id=project_id, organization_id=org.id)

    stmt = (
        select(Secret)
        .options(selectinload(Secret.versions), selectinload(Secret.rotation))
        .where(
            and_(
                Secret.project_id == project_id,
                Secret.environment_id == environment_id,
                Secret.is_deleted == False,
            )
        )
        .order_by(Secret.key)
    )
    res = await db.execute(stmt)
    secrets = res.scalars().all()

    output = []
    for s in secrets:
        latest_ver = s.versions[0] if s.versions else None
        output.append(
            SecretResponse(
                id=s.id,
                project_id=s.project_id,
                environment_id=s.environment_id,
                key=s.key,
                path=path,
                comment=s.comment,
                current_version=s.current_version_num,
                updated_at=latest_ver.created_at if latest_ver else s.updated_at,
                last_actor_name=latest_ver.actor_name if latest_ver else None,
                rotation_interval=f"{s.rotation.interval_seconds // 86400} days" if s.rotation else None,
            )
        )
    return output


@router.post("", response_model=SecretResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("secret:create"))])
async def create_secret(
    req: SecretCreate,
    project_id: uuid.UUID = Query(...),
    environment_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    # Strict tenant and environment ownership check
    await get_owned_environment(db=db, environment_id=environment_id, project_id=project_id, organization_id=org.id)

    secret = await secret_service.create_secret(
        db=db,
        project_id=project_id,
        environment_id=environment_id,
        key=req.key,
        value=req.value,
        path=req.path,
        comment=req.comment,
        actor_id=user.id,
        actor_name=user.full_name,
        rotation_interval_days=req.rotation_interval_days,
    )
    return SecretResponse(
        id=secret.id,
        project_id=secret.project_id,
        environment_id=secret.environment_id,
        key=secret.key,
        path=req.path,
        comment=secret.comment,
        current_version=secret.current_version_num,
        updated_at=secret.created_at,
        last_actor_name=user.full_name,
    )


@router.get("/value", response_model=SecretRevealResponse, dependencies=[Depends(require_permission("secret:reveal"))])
async def get_secret_value_by_key(
    project_id: uuid.UUID = Query(...),
    environment_id: uuid.UUID = Query(...),
    key: str = Query(...),
    justification: str | None = Query(None, description="Optional incident/ticket justification"),
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Direct single-query endpoint to decrypt and retrieve a secret value by key name."""
    await check_rate_limit(f"secret_reveal:{user.id}:{org.id}", max_requests=30, window_seconds=60)
    await get_owned_environment(db=db, environment_id=environment_id, project_id=project_id, organization_id=org.id)

    stmt = select(Secret).where(
        and_(
            Secret.project_id == project_id,
            Secret.environment_id == environment_id,
            Secret.key == key.strip().upper(),
            Secret.is_deleted == False,
        )
    )
    res = await db.execute(stmt)
    secret = res.scalar_one_or_none()
    if not secret:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Secret with key '{key}' not found")

    secret, plaintext = await secret_service.reveal_secret(
        db=db,
        secret_id=secret.id,
        actor_id=user.id,
        actor_name=user.full_name,
        justification=justification,
    )
    return SecretRevealResponse(
        id=secret.id,
        key=secret.key,
        value=plaintext,
        version=secret.current_version_num,
        updated_at=secret.updated_at,
    )


@router.get("/{secret_id}/reveal", response_model=SecretRevealResponse, dependencies=[Depends(require_permission("secret:reveal"))])
async def reveal_secret(
    secret_id: uuid.UUID,
    justification: str | None = Query(None, description="Optional incident/ticket justification"),
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Dedicated endpoint to decrypt and retrieve a secret. Emits an audited secret.reveal event with optional justification."""
    await check_rate_limit(f"secret_reveal:{user.id}:{org.id}", max_requests=30, window_seconds=60)
    secret = await get_owned_secret(db=db, secret_id=secret_id, organization_id=org.id)

    secret, plaintext = await secret_service.reveal_secret(
        db=db,
        secret_id=secret.id,
        actor_id=user.id,
        actor_name=user.full_name,
        justification=justification,
    )
    return SecretRevealResponse(
        id=secret.id,
        key=secret.key,
        value=plaintext,
        version=secret.current_version_num,
        updated_at=secret.updated_at,
    )


@router.put("/{secret_id}", response_model=SecretResponse, dependencies=[Depends(require_permission("secret:update"))])
async def update_secret(
    secret_id: uuid.UUID,
    req: SecretUpdate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    secret = await get_owned_secret(db=db, secret_id=secret_id, organization_id=org.id)

    secret = await secret_service.update_secret(
        db=db,
        secret_id=secret.id,
        value=req.value,
        comment=req.comment,
        change_message=req.change_message,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return SecretResponse(
        id=secret.id,
        project_id=secret.project_id,
        environment_id=secret.environment_id,
        key=secret.key,
        path="/",
        comment=secret.comment,
        current_version=secret.current_version_num,
        updated_at=secret.updated_at,
        last_actor_name=user.full_name,
    )


@router.get("/{secret_id}/versions", response_model=list[SecretVersionResponse], dependencies=[Depends(require_permission("secret:read"))])
async def list_secret_versions(
    secret_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    secret = await get_owned_secret(db=db, secret_id=secret_id, organization_id=org.id)

    stmt = (
        select(SecretVersion)
        .where(SecretVersion.secret_id == secret.id)
        .order_by(desc(SecretVersion.version))
    )
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/{secret_id}/rollback", response_model=SecretResponse, dependencies=[Depends(require_permission("secret:rollback"))])
async def rollback_secret(
    secret_id: uuid.UUID,
    req: RollbackRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    secret = await get_owned_secret(db=db, secret_id=secret_id, organization_id=org.id)

    secret = await secret_service.rollback_secret(
        db=db,
        secret_id=secret.id,
        target_version_num=req.target_version,
        reason=req.reason,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return SecretResponse(
        id=secret.id,
        project_id=secret.project_id,
        environment_id=secret.environment_id,
        key=secret.key,
        path="/",
        comment=secret.comment,
        current_version=secret.current_version_num,
        updated_at=secret.updated_at,
        last_actor_name=user.full_name,
    )


@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_permission("secret:delete"))])
async def delete_secret(
    secret_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    secret = await get_owned_secret(db=db, secret_id=secret_id, organization_id=org.id)

    secret.is_deleted = True
    await db.flush()

    await audit_service.log_event(
        db=db,
        organization_id=org.id,
        project_id=secret.project_id,
        actor_id=user.id,
        actor_name=user.full_name,
        action="secret.delete",
        resource_type="secret",
        resource_id=str(secret.id),
        metadata={"key": secret.key},
    )
