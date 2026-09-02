import hashlib
import uuid
from typing import List, Optional, Tuple
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status

from apps.api.app.core.crypto import crypto_engine
from apps.api.app.models.secret import Secret, SecretVersion, SecretFolder
from apps.api.app.models.user import Project
from apps.api.app.services.audit_service import audit_service


class SecretService:
    @staticmethod
    async def create_secret(
        db: AsyncSession,
        project_id: uuid.UUID,
        environment_id: uuid.UUID,
        key: str,
        value: str,
        path: str = "/",
        comment: Optional[str] = None,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
        rotation_interval_days: Optional[int] = None,
    ) -> Secret:
        # 1. Fetch project to verify and get organization_id
        project = await db.get(Project, project_id)
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

        # 2. Check for key duplication in scope
        stmt = select(Secret).where(
            and_(
                Secret.project_id == project_id,
                Secret.environment_id == environment_id,
                Secret.key == key.strip().upper(),
                Secret.is_deleted == False,
            )
        )
        res = await db.execute(stmt)
        if res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Secret key '{key}' already exists in this environment."
            )

        # 3. Envelope encrypt payload for Version 1
        normalized_key = key.strip().upper()
        encrypted_data = crypto_engine.encrypt_secret(
            plaintext=value,
            org_id=str(project.organization_id),
            project_id=str(project_id),
            environment_id=str(environment_id),
            secret_key=normalized_key,
            version=1,
        )

        meta_hash = hashlib.sha256(f"{normalized_key}:{path}:1".encode()).hexdigest()

        # 4. Create Secret entity
        secret = Secret(
            project_id=project_id,
            environment_id=environment_id,
            key=normalized_key,
            comment=comment,
            current_version_num=1,
        )
        db.add(secret)
        await db.flush()

        # 5. Create Version 1 entity
        version = SecretVersion(
            secret_id=secret.id,
            version=1,
            encrypted_value=encrypted_data["ciphertext"],
            nonce=encrypted_data["nonce"],
            encrypted_data_key=encrypted_data["encrypted_data_key"],
            dek_nonce=encrypted_data["dek_nonce"],
            mek_id=encrypted_data["mek_id"],
            mek_version=encrypted_data["mek_version"],
            algorithm=encrypted_data["algorithm"],
            change_type="create",
            change_message="Initial secret creation",
            metadata_hash=meta_hash,
            actor_id=actor_id,
            actor_name=actor_name,
        )
        db.add(version)
        await db.flush()

        # 6. Audit Log
        await audit_service.log_event(
            db=db,
            organization_id=project.organization_id,
            project_id=project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="secret.create",
            resource_type="secret",
            resource_id=str(secret.id),
            metadata={"key": normalized_key, "path": path, "version": 1},
        )

        return secret

    @staticmethod
    async def reveal_secret(
        db: AsyncSession,
        secret_id: uuid.UUID,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
        justification: Optional[str] = None,
    ) -> Tuple[Secret, str]:
        """Decrypts and returns secret value. Generates high-priority audit event."""
        stmt = (
            select(Secret)
            .options(selectinload(Secret.versions))
            .where(and_(Secret.id == secret_id, Secret.is_deleted == False))
        )
        res = await db.execute(stmt)
        secret = res.scalar_one_or_none()
        if not secret or not secret.versions:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

        project = await db.get(Project, secret.project_id)
        latest_version = secret.versions[0]  # sorted desc by version

        # Decrypt payload
        plaintext = crypto_engine.decrypt_secret(
            encrypted_payload={
                "ciphertext": latest_version.encrypted_value,
                "nonce": latest_version.nonce,
                "encrypted_data_key": latest_version.encrypted_data_key,
                "dek_nonce": latest_version.dek_nonce,
                "mek_id": latest_version.mek_id,
                "mek_version": latest_version.mek_version,
            },
            org_id=str(project.organization_id),
            project_id=str(secret.project_id),
            environment_id=str(secret.environment_id),
            secret_key=secret.key,
            version=latest_version.version,
        )

        audit_meta = {"key": secret.key, "version": latest_version.version}
        if justification:
            audit_meta["justification"] = justification

        # Audit Reveal
        await audit_service.log_event(
            db=db,
            organization_id=project.organization_id,
            project_id=secret.project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="secret.reveal",
            resource_type="secret",
            resource_id=str(secret.id),
            metadata=audit_meta,
        )

        return secret, plaintext

    @staticmethod
    async def update_secret(
        db: AsyncSession,
        secret_id: uuid.UUID,
        value: str,
        comment: Optional[str] = None,
        change_message: Optional[str] = None,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> Secret:
        stmt = (
            select(Secret)
            .options(selectinload(Secret.versions))
            .where(and_(Secret.id == secret_id, Secret.is_deleted == False))
        )
        res = await db.execute(stmt)
        secret = res.scalar_one_or_none()
        if not secret:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

        project = await db.get(Project, secret.project_id)
        next_version = secret.current_version_num + 1

        encrypted_data = crypto_engine.encrypt_secret(
            plaintext=value,
            org_id=str(project.organization_id),
            project_id=str(secret.project_id),
            environment_id=str(secret.environment_id),
            secret_key=secret.key,
            version=next_version,
        )

        version = SecretVersion(
            secret_id=secret.id,
            version=next_version,
            encrypted_value=encrypted_data["ciphertext"],
            nonce=encrypted_data["nonce"],
            encrypted_data_key=encrypted_data["encrypted_data_key"],
            dek_nonce=encrypted_data["dek_nonce"],
            mek_id=encrypted_data["mek_id"],
            mek_version=encrypted_data["mek_version"],
            algorithm=encrypted_data["algorithm"],
            change_type="update",
            change_message=change_message or f"Updated to version {next_version}",
            actor_id=actor_id,
            actor_name=actor_name,
        )
        db.add(version)
        secret.current_version_num = next_version
        if comment is not None:
            secret.comment = comment
        await db.flush()

        # Audit
        await audit_service.log_event(
            db=db,
            organization_id=project.organization_id,
            project_id=secret.project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="secret.update",
            resource_type="secret",
            resource_id=str(secret.id),
            metadata={"key": secret.key, "version": next_version},
        )

        return secret

    @staticmethod
    async def rollback_secret(
        db: AsyncSession,
        secret_id: uuid.UUID,
        target_version_num: int,
        reason: Optional[str] = None,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> Secret:
        """Rolls back to historical version by decrypting it and producing a new immutable head version."""
        stmt = (
            select(Secret)
            .options(selectinload(Secret.versions))
            .where(and_(Secret.id == secret_id, Secret.is_deleted == False))
        )
        res = await db.execute(stmt)
        secret = res.scalar_one_or_none()
        if not secret:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

        # Find target version
        target_version = next((v for v in secret.versions if v.version == target_version_num), None)
        if not target_version:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target version {target_version_num} not found"
            )

        project = await db.get(Project, secret.project_id)

        # Decrypt target version
        recovered_plaintext = crypto_engine.decrypt_secret(
            encrypted_payload={
                "ciphertext": target_version.encrypted_value,
                "nonce": target_version.nonce,
                "encrypted_data_key": target_version.encrypted_data_key,
                "dek_nonce": target_version.dek_nonce,
                "mek_id": target_version.mek_id,
                "mek_version": target_version.mek_version,
            },
            org_id=str(project.organization_id),
            project_id=str(secret.project_id),
            environment_id=str(secret.environment_id),
            secret_key=secret.key,
            version=target_version.version,
        )

        # Create new version from recovered plaintext
        new_version_num = secret.current_version_num + 1
        encrypted_data = crypto_engine.encrypt_secret(
            plaintext=recovered_plaintext,
            org_id=str(project.organization_id),
            project_id=str(secret.project_id),
            environment_id=str(secret.environment_id),
            secret_key=secret.key,
            version=new_version_num,
        )

        version = SecretVersion(
            secret_id=secret.id,
            version=new_version_num,
            encrypted_value=encrypted_data["ciphertext"],
            nonce=encrypted_data["nonce"],
            encrypted_data_key=encrypted_data["encrypted_data_key"],
            dek_nonce=encrypted_data["dek_nonce"],
            mek_id=encrypted_data["mek_id"],
            mek_version=encrypted_data["mek_version"],
            algorithm=encrypted_data["algorithm"],
            change_type="rollback",
            change_message=f"Rollback to v{target_version_num}: {reason or 'No reason provided'}",
            actor_id=actor_id,
            actor_name=actor_name,
        )
        db.add(version)
        secret.current_version_num = new_version_num
        await db.flush()

        # Audit
        await audit_service.log_event(
            db=db,
            organization_id=project.organization_id,
            project_id=secret.project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="secret.rollback",
            resource_type="secret",
            resource_id=str(secret.id),
            metadata={"key": secret.key, "from_version": target_version_num, "to_version": new_version_num},
        )

        return secret


secret_service = SecretService()
