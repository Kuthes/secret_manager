import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db
from apps.api.app.models.kms import ManagedKey
from apps.api.app.models.user import User, Organization
from apps.api.app.schemas.kms import (
    KeyCreateRequest,
    KeyResponse,
    EncryptRequest,
    EncryptResponse,
    DecryptRequest,
    DecryptResponse,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)
from apps.api.app.services.kms_service import kms_service
from apps.api.app.api.deps import get_current_user, get_current_org, require_permission

router = APIRouter(prefix="/kms", tags=["KMS"])


@router.get("/keys", response_model=List[KeyResponse], dependencies=[Depends(require_permission("kms:list"))])
async def list_keys(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = select(ManagedKey).where(and_(ManagedKey.organization_id == org.id, ManagedKey.is_deleted == False))
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/keys", response_model=KeyResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("kms:create"))])
async def create_key(
    req: KeyCreateRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    key = await kms_service.create_key(
        db=db,
        organization_id=org.id,
        name=req.name,
        algorithm=req.algorithm,
        key_usage=req.key_usage,
        project_id=req.project_id,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return key


@router.post("/keys/{key_id}/encrypt", response_model=EncryptResponse, dependencies=[Depends(require_permission("kms:encrypt"))])
async def encrypt_data(
    key_id: uuid.UUID,
    req: EncryptRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    key = await db.get(ManagedKey, key_id)
    if not key or key.is_deleted or key.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    ct, nonce, ver = await kms_service.encrypt(
        db=db,
        key_id=key_id,
        plaintext=req.plaintext,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return EncryptResponse(
        key_id=key_id,
        key_version=ver,
        ciphertext=ct,
        nonce=nonce,
    )


@router.post("/keys/{key_id}/decrypt", response_model=DecryptResponse, dependencies=[Depends(require_permission("kms:decrypt"))])
async def decrypt_data(
    key_id: uuid.UUID,
    req: DecryptRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    key = await db.get(ManagedKey, key_id)
    if not key or key.is_deleted or key.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    pt = await kms_service.decrypt(
        db=db,
        key_id=key_id,
        ciphertext_b64=req.ciphertext,
        nonce_b64=req.nonce,
        version=req.version,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return DecryptResponse(
        key_id=key_id,
        plaintext=pt,
    )


@router.post("/keys/{key_id}/rotate", response_model=KeyResponse, dependencies=[Depends(require_permission("kms:rotate"))])
async def rotate_key(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    key = await db.get(ManagedKey, key_id)
    if not key or key.is_deleted or key.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    rotated = await kms_service.rotate_key(
        db=db,
        key_id=key_id,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return rotated


@router.post("/keys/{key_id}/sign", response_model=SignResponse, dependencies=[Depends(require_permission("kms:sign"))])
async def sign_data(
    key_id: uuid.UUID,
    req: SignRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    key = await db.get(ManagedKey, key_id)
    if not key or key.is_deleted or key.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    signature, ver = await kms_service.sign(
        db=db,
        key_id=key_id,
        message=req.message,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return SignResponse(
        key_id=key_id,
        key_version=ver,
        signature=signature,
    )


@router.post("/keys/{key_id}/verify", response_model=VerifyResponse, dependencies=[Depends(require_permission("kms:verify"))])
async def verify_data(
    key_id: uuid.UUID,
    req: VerifyRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    key = await db.get(ManagedKey, key_id)
    if not key or key.is_deleted or key.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    is_valid = await kms_service.verify(
        db=db,
        key_id=key_id,
        message=req.message,
        signature_b64=req.signature,
        version=req.version,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return VerifyResponse(
        key_id=key_id,
        valid=is_valid,
    )


@router.post("/keys/{key_id}/disable", response_model=KeyResponse, dependencies=[Depends(require_permission("kms:disable"))])
async def disable_key(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    key = await db.get(ManagedKey, key_id)
    if not key or key.is_deleted or key.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    key.status = "disabled"
    await db.flush()
    return key
