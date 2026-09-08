import uuid

from fastapi import HTTPException, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.models.dynamic_secret import (
    DynamicCredentialLease,
    DynamicSecretProvider,
)
from apps.api.app.models.integration import IntegrationConnection, SecretSync
from apps.api.app.models.kms import ManagedKey
from apps.api.app.models.pam import AccessRequest, AccessResource
from apps.api.app.models.pki import Certificate, CertificateAuthority
from apps.api.app.models.secret import Secret
from apps.api.app.models.user import Environment, Project


async def get_owned_project(
    db: AsyncSession,
    project_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> Project:
    """Fetch project verifying it belongs to the authenticated organization."""
    stmt = (
        select(Project)
        .where(
            and_(
                Project.id == project_id,
                Project.organization_id == organization_id,
                Project.is_deleted == False,
            )
        )
    )
    res = await db.execute(stmt)
    project = res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


async def get_owned_environment(
    db: AsyncSession,
    environment_id: uuid.UUID,
    project_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> Environment:
    """Fetch environment verifying it belongs to the given project and authenticated organization."""
    # First ensure project is owned
    await get_owned_project(db=db, project_id=project_id, organization_id=organization_id)

    stmt = select(Environment).where(
        and_(
            Environment.id == environment_id,
            Environment.project_id == project_id,
        )
    )
    res = await db.execute(stmt)
    env = res.scalar_one_or_none()
    if not env:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found")
    return env


async def get_owned_secret(
    db: AsyncSession,
    secret_id: uuid.UUID,
    organization_id: uuid.UUID,
    load_versions: bool = False,
    load_rotation: bool = False,
) -> Secret:
    """Fetch secret verifying it belongs to the authenticated organization via project relationship."""
    stmt = (
        select(Secret)
        .join(Project, Secret.project_id == Project.id)
        .where(
            and_(
                Secret.id == secret_id,
                Project.organization_id == organization_id,
                Secret.is_deleted == False,
                Project.is_deleted == False,
            )
        )
    )
    if load_versions:
        stmt = stmt.options(selectinload(Secret.versions))
    if load_rotation:
        stmt = stmt.options(selectinload(Secret.rotation))

    res = await db.execute(stmt)
    secret = res.scalar_one_or_none()
    if not secret:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")
    return secret


async def get_owned_ca(
    db: AsyncSession,
    ca_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> CertificateAuthority:
    """Fetch CA verifying it belongs to the authenticated organization."""
    stmt = select(CertificateAuthority).where(
        and_(
            CertificateAuthority.id == ca_id,
            CertificateAuthority.organization_id == organization_id,
        )
    )
    res = await db.execute(stmt)
    ca = res.scalar_one_or_none()
    if not ca:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate Authority not found")
    return ca


async def get_owned_certificate(
    db: AsyncSession,
    cert_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> Certificate:
    """Fetch certificate verifying its parent CA belongs to the authenticated organization."""
    stmt = (
        select(Certificate)
        .join(CertificateAuthority, Certificate.ca_id == CertificateAuthority.id)
        .where(
            and_(
                Certificate.id == cert_id,
                CertificateAuthority.organization_id == organization_id,
            )
        )
    )
    res = await db.execute(stmt)
    cert = res.scalar_one_or_none()
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")
    return cert


async def get_owned_kms_key(
    db: AsyncSession,
    key_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> ManagedKey:
    """Fetch KMS key verifying it belongs to the authenticated organization."""
    stmt = select(ManagedKey).where(
        and_(
            ManagedKey.id == key_id,
            ManagedKey.organization_id == organization_id,
            ManagedKey.is_deleted == False,
        )
    )
    res = await db.execute(stmt)
    key = res.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
    return key


async def get_owned_dynamic_provider(
    db: AsyncSession,
    provider_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> DynamicSecretProvider:
    """Fetch dynamic secret provider verifying its project belongs to the authenticated organization."""
    stmt = (
        select(DynamicSecretProvider)
        .join(Project, DynamicSecretProvider.project_id == Project.id)
        .where(
            and_(
                DynamicSecretProvider.id == provider_id,
                Project.organization_id == organization_id,
                Project.is_deleted == False,
            )
        )
    )
    res = await db.execute(stmt)
    provider = res.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dynamic provider not found or inactive")
    return provider


async def get_owned_dynamic_lease(
    db: AsyncSession,
    lease_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> DynamicCredentialLease:
    """Fetch dynamic credential lease verifying its provider and project belong to the authenticated organization."""
    stmt = (
        select(DynamicCredentialLease)
        .join(DynamicSecretProvider, DynamicCredentialLease.provider_id == DynamicSecretProvider.id)
        .join(Project, DynamicSecretProvider.project_id == Project.id)
        .where(
            and_(
                DynamicCredentialLease.id == lease_id,
                Project.organization_id == organization_id,
                Project.is_deleted == False,
            )
        )
    )
    res = await db.execute(stmt)
    lease = res.scalar_one_or_none()
    if not lease:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lease not found")
    return lease


async def get_owned_integration(
    db: AsyncSession,
    connection_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> IntegrationConnection:
    """Fetch integration connection verifying it belongs to the authenticated organization."""
    stmt = select(IntegrationConnection).where(
        and_(
            IntegrationConnection.id == connection_id,
            IntegrationConnection.organization_id == organization_id,
        )
    )
    res = await db.execute(stmt)
    conn = res.scalar_one_or_none()
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration connection not found")
    return conn


async def get_owned_sync(
    db: AsyncSession,
    sync_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> SecretSync:
    """Fetch secret sync verifying its integration connection belongs to the authenticated organization."""
    stmt = (
        select(SecretSync)
        .join(IntegrationConnection, SecretSync.connection_id == IntegrationConnection.id)
        .where(
            and_(
                SecretSync.id == sync_id,
                IntegrationConnection.organization_id == organization_id,
            )
        )
    )
    res = await db.execute(stmt)
    sync = res.scalar_one_or_none()
    if not sync:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret sync not found")
    return sync


async def get_owned_pam_resource(
    db: AsyncSession,
    resource_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> AccessResource:
    """Fetch PAM access resource verifying it belongs to the authenticated organization."""
    stmt = select(AccessResource).where(
        and_(
            AccessResource.id == resource_id,
            AccessResource.organization_id == organization_id,
        )
    )
    res = await db.execute(stmt)
    resource = res.scalar_one_or_none()
    if not resource:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protected resource not found")
    return resource


async def get_owned_pam_request(
    db: AsyncSession,
    request_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> AccessRequest:
    """Fetch PAM access request verifying its target resource belongs to the authenticated organization."""
    stmt = (
        select(AccessRequest)
        .join(AccessResource, AccessRequest.resource_id == AccessResource.id)
        .options(selectinload(AccessRequest.resource))
        .where(
            and_(
                AccessRequest.id == request_id,
                AccessResource.organization_id == organization_id,
            )
        )
    )
    res = await db.execute(stmt)
    access_req = res.scalar_one_or_none()
    if not access_req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found")
    return access_req
