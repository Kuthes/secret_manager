import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.db.session import get_db
from apps.api.app.models.user import Organization, Project, Environment, User
from apps.api.app.schemas.project import OrganizationResponse, ProjectCreate, ProjectResponse, EnvironmentResponse
from apps.api.app.api.deps import get_current_user, get_current_org, require_permission

router = APIRouter(tags=["Projects & Tenancy"])


@router.get("/organizations/current", response_model=OrganizationResponse)
async def get_current_organization(org: Organization = Depends(get_current_org)):
    return org


@router.get("/projects", response_model=List[ProjectResponse], dependencies=[Depends(require_permission("project:list"))])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    stmt = (
        select(Project)
        .options(selectinload(Project.environments))
        .where(and_(Project.organization_id == org.id, Project.is_deleted == False))
        .order_by(Project.name)
    )
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("project:create"))])
async def create_project(
    req: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    slug = req.slug or req.name.lower().replace(" ", "-")
    project = Project(
        organization_id=org.id,
        name=req.name,
        slug=slug,
        description=req.description,
    )
    db.add(project)
    await db.flush()

    # Create default standard environments
    env_dev = Environment(project_id=project.id, name="Development", slug="development", position=0)
    env_stage = Environment(project_id=project.id, name="Staging", slug="staging", position=1)
    env_prod = Environment(project_id=project.id, name="Production", slug="production", position=2)
    db.add_all([env_dev, env_stage, env_prod])
    await db.flush()

    stmt = select(Project).options(selectinload(Project.environments)).where(Project.id == project.id)
    res = await db.execute(stmt)
    return res.scalar_one()


@router.get("/projects/{project_id}/environments", response_model=List[EnvironmentResponse], dependencies=[Depends(require_permission("project:read"))])
async def list_environments(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    # Strict tenant check
    project = await db.get(Project, project_id)
    if not project or project.is_deleted or project.organization_id != org.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    stmt = select(Environment).where(Environment.project_id == project_id).order_by(Environment.position)
    res = await db.execute(stmt)
    return res.scalars().all()
