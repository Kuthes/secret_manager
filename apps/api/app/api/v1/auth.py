import uuid
from fastapi import APIRouter, Depends, Response, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.config import settings
from apps.api.app.db.session import get_db
from apps.api.app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    UserResponse,
    MFASetupResponse,
    MFAVerifyRequest,
    UniversalAuthRequest,
    KubernetesAuthRequest,
    MachineTokenResponse,
)
from apps.api.app.services.auth_service import auth_service
from apps.api.app.api.deps import get_current_user, get_current_org
from apps.api.app.models.user import User, Organization

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, response: Response, db: AsyncSession = Depends(get_db)):
    user, org, token = await auth_service.register_user(
        db=db,
        email=req.email,
        password=req.password,
        full_name=req.full_name,
        org_name=req.org_name,
    )
    is_prod = settings.ENVIRONMENT == "production"
    response.set_cookie(
        key="aegis_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=is_prod,
        max_age=86400,
    )
    return TokenResponse(
        access_token=token,
        expires_in=86400,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        org_id=org.id if org else None,
        org_name=org.name if org else None,
        role="owner",
    )


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    user, org, token = await auth_service.authenticate_user(
        db=db,
        email=req.email,
        password=req.password,
        mfa_code=req.mfa_code,
    )
    is_prod = settings.ENVIRONMENT == "production"
    response.set_cookie(
        key="aegis_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=is_prod,
        max_age=86400,
    )
    role_slug = user.memberships[0].role.slug if (user.memberships and user.memberships[0].role) else "viewer"
    return TokenResponse(
        access_token=token,
        expires_in=86400,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        org_id=org.id if org else None,
        org_name=org.name if org else None,
        role=role_slug,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("aegis_session")
    return {"message": "Logged out successfully"}


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    secret, qr_uri, recovery_codes = await auth_service.setup_mfa(db, current_user)
    return MFASetupResponse(
        secret=secret,
        otpauth_uri=qr_uri,
        recovery_codes=recovery_codes,
    )


@router.post("/mfa/verify")
async def verify_mfa(
    req: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    success = await auth_service.verify_and_enable_mfa(db, current_user, req.code)
    return {"status": "success", "mfa_enabled": True}


@router.post("/machine/universal", response_model=MachineTokenResponse)
async def machine_universal_auth(
    req: UniversalAuthRequest,
    db: AsyncSession = Depends(get_db),
):
    ident, token = await auth_service.authenticate_universal_machine(
        db=db,
        client_id=req.client_id,
        client_secret=req.client_secret,
    )
    return MachineTokenResponse(
        access_token=token,
        expires_in=3600,
        identity_type="universal_auth",
        identity_name=ident.name,
        org_id=ident.organization_id,
    )


@router.post("/machine/kubernetes", response_model=MachineTokenResponse)
async def machine_kubernetes_auth(
    req: KubernetesAuthRequest,
    x_org_id: str = Header(..., alias="X-Organization-Id"),
    db: AsyncSession = Depends(get_db),
):
    try:
        org_id = uuid.UUID(x_org_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid organization ID in header")

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    token = await auth_service.authenticate_kubernetes_machine(
        db=db,
        org_id=org.id,
        sa_jwt=req.jwt,
    )
    return MachineTokenResponse(
        access_token=token,
        expires_in=3600,
        identity_type="kubernetes_auth",
        identity_name="k8s-pod",
        org_id=org.id,
    )
