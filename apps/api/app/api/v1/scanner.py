import uuid
from typing import List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.db.session import get_db
from apps.api.app.models.scanner import ScannerRepository, ScanJob, ScanFinding
from apps.api.app.models.user import Project, Organization
from apps.api.app.schemas.scanner import ScannerRepoCreate, ScannerRepoResponse, ScanFindingResponse
from apps.api.app.services.scanner_service import scanner_service
from apps.api.app.api.deps import get_current_org, require_permission

router = APIRouter(prefix="/scanner", tags=["Secret Scanner"])


class ScanPayloadRequest(BaseModel):
    project_id: uuid.UUID
    content: str = Field(..., description="File or source content string to scan")
    file_path: str = Field(default="payload.env")


@router.get("/repositories", response_model=List[ScannerRepoResponse], dependencies=[Depends(require_permission("scanner:read"))])
async def list_repositories(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = (
        select(ScannerRepository)
        .join(Project)
        .where(Project.organization_id == org.id)
    )
    res = await db.execute(stmt)
    return res.scalars().all()


@router.get("/findings", response_model=List[ScanFindingResponse], dependencies=[Depends(require_permission("scanner:read"))])
async def list_findings(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = (
        select(ScanFinding)
        .join(ScanJob)
        .join(ScannerRepository)
        .join(Project)
        .where(Project.organization_id == org.id)
        .order_by(desc(ScanFinding.created_at))
    )
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/scan", response_model=List[ScanFindingResponse], dependencies=[Depends(require_permission("scanner:scan"))])
async def scan_content(
    req: ScanPayloadRequest,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    project = await db.get(Project, req.project_id)
    if not project or project.is_deleted or project.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    findings_data = scanner_service.scan_content(req.content, file_path=req.file_path)
    
    stmt = select(ScannerRepository).where(ScannerRepository.project_id == req.project_id)
    res = await db.execute(stmt)
    repo = res.scalar_one_or_none()
    if not repo:
        repo = ScannerRepository(project_id=req.project_id, repo_url="inline-scan", default_branch="main")
        db.add(repo)
        await db.flush()

    job = ScanJob(repository_id=repo.id, findings_count=len(findings_data))
    db.add(job)
    await db.flush()

    recorded = await scanner_service.record_findings(db=db, job_id=job.id, findings_data=findings_data)
    return recorded
