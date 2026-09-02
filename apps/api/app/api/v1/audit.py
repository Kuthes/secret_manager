import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db
from apps.api.app.models.audit import AuditEvent
from apps.api.app.models.user import Organization
from apps.api.app.schemas.audit import AuditEventResponse
from apps.api.app.services.audit_service import audit_service
from apps.api.app.api.deps import get_current_org, require_permission

router = APIRouter(prefix="/audit", tags=["Audit Log"])


@router.get("/events", response_model=List[AuditEventResponse], dependencies=[Depends(require_permission("audit:read"))])
async def list_audit_events(
    project_id: Optional[uuid.UUID] = Query(None),
    action: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    conditions = [AuditEvent.organization_id == org.id]
    if project_id:
        conditions.append(AuditEvent.project_id == project_id)
    if action:
        conditions.append(AuditEvent.action.ilike(f"%{action}%"))

    stmt = select(AuditEvent).where(and_(*conditions)).order_by(desc(AuditEvent.created_at)).limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/verify", dependencies=[Depends(require_permission("audit:read"))])
async def verify_audit_chain(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    """Cryptographically verify the organization's audit event SHA-256 hash chain."""
    result = await audit_service.verify_chain(db=db, organization_id=org.id)
    return result


@router.get("/export", dependencies=[Depends(require_permission("audit:export"))])
async def export_audit_events(
    format: str = Query("json", pattern="^(json|csv)$"),
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    """Export sanitized, tamper-evident audit logs in JSON or CSV format."""
    content = await audit_service.export_events(db=db, organization_id=org.id, format_type=format)
    media_type = "text/csv" if format == "csv" else "application/json"
    filename = f"audit-export-{org.slug}.{format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
