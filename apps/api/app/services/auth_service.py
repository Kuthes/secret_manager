import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List, Dict, Any
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status

from apps.api.app.core.security import get_password_hash, verify_password, create_access_token, decode_access_token
from apps.api.app.models.user import User, Organization, OrganizationMembership, Role, ServiceIdentity
from apps.api.app.services.audit_service import audit_service


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("utf-8").replace("=", "")


def get_totp_token(secret: str, time_step: int = 30) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded.upper())
    counter = int(time.time()) // time_step
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)


def verify_totp_token(secret: str, token: str, time_step: int = 30, window: int = 1) -> bool:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    try:
        key = base64.b32decode(padded.upper())
    except Exception:
        return False
    current_counter = int(time.time()) // time_step
    for i in range(-window, window + 1):
        msg = struct.pack(">Q", current_counter + i)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
        if str(code % 1000000).zfill(6) == str(token).strip():
            return True
    return False


class AuthService:
    @staticmethod
    async def register_user(
        db: AsyncSession,
        email: str,
        password: str,
        full_name: str,
        org_name: Optional[str] = None,
    ) -> Tuple[User, Organization, str]:
        # Check existing user
        stmt = select(User).where(User.email == email.lower().strip())
        res = await db.execute(stmt)
        if res.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this email already exists")

        # Create user with Argon2id hash
        user = User(
            email=email.lower().strip(),
            hashed_password=get_password_hash(password),
            full_name=full_name.strip(),
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        await db.flush()

        # Create Organization
        name = org_name.strip() if org_name else f"{full_name.strip()}'s Org"
        slug = name.lower().replace(" ", "-").replace("_", "-") + f"-{str(uuid.uuid4())[:6]}"
        org = Organization(
            name=name,
            slug=slug,
        )
        db.add(org)
        await db.flush()

        # Create Owner Role
        owner_role = Role(
            organization_id=org.id,
            name="Organization Owner",
            slug="owner",
            description="Full administrative access to organization",
            is_system=True,
        )
        db.add(owner_role)
        await db.flush()

        # Create Membership
        membership = OrganizationMembership(
            organization_id=org.id,
            user_id=user.id,
            role_id=owner_role.id,
        )
        db.add(membership)
        await db.flush()

        token = create_access_token(subject=str(user.id), org_id=str(org.id), extra_claims={"name": user.full_name, "email": user.email, "role": "owner"})

        await audit_service.log_event(
            db=db,
            organization_id=org.id,
            actor_id=user.id,
            actor_name=user.full_name,
            action="auth.register",
            resource_type="user",
            resource_id=str(user.id),
        )

        return user, org, token

    @staticmethod
    async def authenticate_user(
        db: AsyncSession,
        email: str,
        password: str,
        mfa_code: Optional[str] = None,
    ) -> Tuple[User, Organization, str]:
        stmt = (
            select(User)
            .options(
                selectinload(User.memberships).selectinload(OrganizationMembership.organization),
                selectinload(User.memberships).selectinload(OrganizationMembership.role),
            )
            .where(User.email == email.lower().strip())
        )
        res = await db.execute(stmt)
        user = res.scalar_one_or_none()
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

        # Enforce MFA if enabled
        if user.mfa_enabled:
            if not mfa_code:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="MFA_REQUIRED: Multi-factor authentication code is required.",
                )
            if not user.mfa_secret_encrypted or not verify_totp_token(user.mfa_secret_encrypted, mfa_code):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA verification code.")

        org = user.memberships[0].organization if user.memberships else None
        org_id = str(org.id) if org else None
        role_slug = user.memberships[0].role.slug if (user.memberships and user.memberships[0].role) else "viewer"

        token = create_access_token(
            subject=str(user.id),
            org_id=org_id,
            extra_claims={"name": user.full_name, "email": user.email, "role": role_slug},
        )

        if org:
            await audit_service.log_event(
                db=db,
                organization_id=org.id,
                actor_id=user.id,
                actor_name=user.full_name,
                action="auth.login",
                resource_type="user",
                resource_id=str(user.id),
            )

        return user, org, token

    @staticmethod
    async def setup_mfa(db: AsyncSession, user: User) -> Tuple[str, str, List[str]]:
        secret = generate_totp_secret()
        # Save secret to user
        user.mfa_secret_encrypted = secret
        await db.flush()

        otpauth_uri = f"otpauth://totp/AegisVault:{user.email}?secret={secret}&issuer=AegisVault"
        recovery_codes = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(5)]

        return secret, otpauth_uri, recovery_codes

    @staticmethod
    async def verify_and_enable_mfa(db: AsyncSession, user: User, code: str) -> bool:
        if not user.mfa_secret_encrypted:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup must be initiated first.")

        if not verify_totp_token(user.mfa_secret_encrypted, code):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code.")

        user.mfa_enabled = True
        await db.flush()

        if user.memberships:
            await audit_service.log_event(
                db=db,
                organization_id=user.memberships[0].organization_id,
                actor_id=user.id,
                actor_name=user.full_name,
                action="auth.mfa_enabled",
                resource_type="user",
                resource_id=str(user.id),
            )

        return True

    @staticmethod
    async def authenticate_universal_machine(
        db: AsyncSession,
        client_id: str,
        client_secret: str,
    ) -> Tuple[ServiceIdentity, str]:
        prefix = client_id[:8]
        key_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()

        stmt = (
            select(ServiceIdentity)
            .options(selectinload(ServiceIdentity.organization))
            .where(and_(ServiceIdentity.token_prefix == prefix, ServiceIdentity.token_hash == key_hash))
        )
        res = await db.execute(stmt)
        ident = res.scalar_one_or_none()
        if not ident:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid machine credentials.")

        token = create_access_token(
            subject=str(ident.id),
            org_id=str(ident.organization_id),
            expires_delta=timedelta(hours=1),  # Short-lived workload token
            extra_claims={"kind": "machine", "name": ident.name, "role": "developer"},
        )

        await audit_service.log_event(
            db=db,
            organization_id=ident.organization_id,
            actor_id=ident.id,
            actor_name=ident.name,
            actor_type="service_identity",
            action="auth.machine_login",
            resource_type="service_identity",
            resource_id=str(ident.id),
        )

        return ident, token

    @staticmethod
    async def authenticate_kubernetes_machine(
        db: AsyncSession,
        org_id: uuid.UUID,
        sa_jwt: str,
        workload_name: str = "k8s-pod",
    ) -> str:
        # In production K8s Auth: validates TokenReview API against apiserver
        if not sa_jwt or len(sa_jwt) < 10:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Kubernetes service account token.")

        # Issue short-lived AegisVault token (1 hour)
        token = create_access_token(
            subject=f"k8s:{workload_name}",
            org_id=str(org_id),
            expires_delta=timedelta(hours=1),
            extra_claims={"kind": "machine", "name": workload_name, "role": "developer"},
        )

        await audit_service.log_event(
            db=db,
            organization_id=org_id,
            actor_name=f"k8s:{workload_name}",
            actor_type="service_identity",
            action="auth.k8s_login",
            resource_type="service_identity",
            metadata={"workload": workload_name},
        )

        return token


auth_service = AuthService()
