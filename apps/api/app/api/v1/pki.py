import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db
from apps.api.app.models.pki import CertificateAuthority, Certificate
from apps.api.app.models.user import User, Organization
from apps.api.app.schemas.pki import CACreateRequest, CAResponse, CertIssueRequest, CertResponse, CertRevokeRequest
from apps.api.app.services.pki_service import pki_service
from apps.api.app.api.deps import get_current_user, get_current_org, require_permission

router = APIRouter(prefix="/pki", tags=["PKI & Certificates"])


@router.get("/ca", response_model=List[CAResponse], dependencies=[Depends(require_permission("ca:list"))])
async def list_cas(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = select(CertificateAuthority).where(CertificateAuthority.organization_id == org.id)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/ca", response_model=CAResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("ca:create"))])
async def create_ca(
    req: CACreateRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    if req.parent_ca_id:
        parent_ca = await db.get(CertificateAuthority, req.parent_ca_id)
        if not parent_ca or parent_ca.organization_id != org.id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent CA not found in organization")

    ca = await pki_service.create_ca(
        db=db,
        organization_id=org.id,
        name=req.name,
        common_name=req.common_name,
        ca_type=req.ca_type,
        validity_days=req.validity_days,
        parent_ca_id=req.parent_ca_id,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return ca


@router.get("/ca/{ca_id}/crl", dependencies=[Depends(require_permission("ca:read"))])
async def get_ca_crl(
    ca_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    ca = await db.get(CertificateAuthority, ca_id)
    if not ca or ca.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate Authority not found")

    crl_pem = await pki_service.generate_crl(db, ca_id)
    return Response(content=crl_pem, media_type="application/pkix-crl")


@router.get("/certificates", response_model=List[CertResponse], dependencies=[Depends(require_permission("certificate:read"))])
async def list_certificates(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = (
        select(Certificate)
        .join(CertificateAuthority)
        .where(CertificateAuthority.organization_id == org.id)
        .order_by(Certificate.created_at.desc())
    )
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/issue", response_model=CertResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("certificate:issue"))])
async def issue_certificate(
    req: CertIssueRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    ca = await db.get(CertificateAuthority, req.ca_id)
    if not ca or ca.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate Authority not found")

    cert, priv_key_pem = await pki_service.issue_certificate(
        db=db,
        ca_id=req.ca_id,
        common_name=req.common_name,
        san_dns_names=req.san_dns_names,
        validity_days=req.validity_days,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return CertResponse(
        id=cert.id,
        ca_id=cert.ca_id,
        serial_number=cert.serial_number,
        common_name=cert.common_name,
        san_dns_names=cert.san_dns_names,
        cert_pem=cert.cert_pem,
        private_key_pem=priv_key_pem,
        valid_from=cert.valid_from,
        valid_to=cert.valid_to,
        status=cert.status,
    )


@router.post("/certificates/{cert_id}/revoke", response_model=CertResponse, dependencies=[Depends(require_permission("certificate:revoke"))])
async def revoke_certificate(
    cert_id: uuid.UUID,
    req: CertRevokeRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    cert = await db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

    ca = await db.get(CertificateAuthority, cert.ca_id)
    if not ca or ca.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

    cert = await pki_service.revoke_certificate(
        db=db,
        cert_id=cert_id,
        reason=req.reason,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return cert


@router.get("/certificates/{cert_id}/private-key", dependencies=[Depends(require_permission("certificate:read-private-key"))])
async def get_certificate_private_key(
    cert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    cert = await db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

    ca = await db.get(CertificateAuthority, cert.ca_id)
    if not ca or ca.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

    priv_key_pem = await pki_service.reveal_private_key(
        db=db,
        cert_id=cert_id,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return {"private_key_pem": priv_key_pem}
