import uuid
from collections.abc import Callable

from fastapi import Cookie, Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.core.security import decode_access_token
from apps.api.app.db.session import get_db
from apps.api.app.models.user import (
    Organization,
    OrganizationMembership,
    Role,
    User,
)

security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token_header: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    session_cookie: str | None = Cookie(default=None, alias="aegis_session"),
) -> User:
    token = None
    if token_header:
        token = token_header.credentials
    elif session_cookie:
        token = session_cookie

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = uuid.UUID(payload["sub"])
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject identifier",
            headers={"WWW-Authenticate": "Bearer"},
        )

    stmt = (
        select(User)
        .options(
            selectinload(User.memberships).selectinload(OrganizationMembership.organization),
            selectinload(User.memberships).selectinload(OrganizationMembership.role).selectinload(Role.permissions),
        )
        .where(User.id == user_id)
    )
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return user


async def get_current_org(
    user: User = Depends(get_current_user),
    x_org_id: str | None = Header(default=None, alias="X-Organization-Id"),
) -> Organization:
    """
    Canonical organization context resolver.
    - No header: returns user's default active organization membership.
    - Valid header + member: returns requested organization.
    - Valid header + not member: rejects with 403 Forbidden.
    - Malformed header: rejects with 400 Bad Request.
    - NEVER silently falls back when header is present.
    """
    if not user.memberships:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is not a member of any organization")

    if x_org_id is not None:
        try:
            target_id = uuid.UUID(str(x_org_id).strip())
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid organization ID format in header",
            )

        membership = next((m for m in user.memberships if m.organization_id == target_id), None)
        if not membership:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You are not a member of the requested organization",
            )
        return membership.organization

    return user.memberships[0].organization


async def get_current_membership(
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
) -> OrganizationMembership:
    membership = next((m for m in user.memberships if m.organization_id == org.id), None)
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active membership not found in current organization context",
        )
    return membership


# Built-in standard role permission matrix
ROLE_PERMISSIONS = {
    "owner": {"*"},
    "admin": {
        "secret:create", "secret:list", "secret:read", "secret:reveal", "secret:update", "secret:delete", "secret:rollback", "secret:rotate",
        "secret:change_request_create", "secret:change_request_read", "secret:change_request_review", "secret:change_request_apply", "secret:change_request_cancel",
        "ca:create", "ca:manage", "ca:list", "ca:read", "ca:update", "ca:delete", "certificate:list", "certificate:read", "certificate:issue", "certificate:read-private-key", "certificate:renew", "certificate:revoke",
        "kms:create", "kms:list", "kms:encrypt", "kms:decrypt", "kms:sign", "kms:verify", "kms:rotate", "kms:disable",
        "pam:request", "pam:approve", "pam:reject", "pam:revoke", "pam:manage", "pam:admin", "pam:list",
        "audit:read", "audit:export",
        "dynamic:create", "dynamic:list", "dynamic:issue", "dynamic:revoke",
        "agent:create", "agent:read", "agent:session_create", "agent:session_revoke", "agent:proxy", "agent:delete",
        "integration:create", "integration:list", "integration:update", "integration:sync", "integration:delete",
        "project:create", "project:list", "project:read", "project:update", "project:delete",
        "scanner:scan", "scanner:read",
        "member:manage", "role:manage", "settings:manage",
    },
    "developer": {
        "secret:create", "secret:list", "secret:read", "secret:reveal", "secret:update", "secret:rollback", "secret:rotate",
        "secret:change_request_create", "secret:change_request_read", "secret:change_request_cancel",
        "ca:list", "ca:read", "certificate:list", "certificate:read", "certificate:issue", "certificate:renew",
        "kms:list", "kms:encrypt", "kms:decrypt", "kms:sign", "kms:verify",
        "pam:request", "pam:list",
        "audit:read",
        "dynamic:list", "dynamic:issue",
        "agent:read", "agent:session_create", "agent:proxy",
        "integration:list",
        "project:list", "project:read",
        "scanner:scan", "scanner:read",
    },
    "viewer": {
        "secret:list", "secret:read", "secret:change_request_read",
        "ca:list", "ca:read", "certificate:list", "certificate:read",
        "kms:list",
        "pam:list",
        "audit:read",
        "dynamic:list",
        "integration:list",
        "project:list", "project:read",
        "scanner:read",
    },
}


def require_permission(action: str) -> Callable:
    """
    FastAPI dependency factory to enforce centralized RBAC authorization.
    Rejects unauthorized operations with 403 Forbidden.
    """
    async def _dependency(membership: OrganizationMembership = Depends(get_current_membership)) -> None:
        role = membership.role
        role_slug = role.slug.lower() if role and role.slug else "viewer"

        # 1. System Role Matrix Check
        if role_slug in ROLE_PERMISSIONS:
            allowed = ROLE_PERMISSIONS[role_slug]
            if "*" in allowed or action in allowed:
                return

        # 2. Database Explicit Permissions Check (for custom and augmented roles)
        if role and role.permissions:
            for p in role.permissions:
                if p.action == "*" or p.action == action:
                    return

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Permission '{action}' is required for this operation.",
        )

    return _dependency
