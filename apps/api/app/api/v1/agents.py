import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.api.deps import get_current_org, get_current_user, require_permission
from apps.api.app.db.session import get_db
from apps.api.app.models.user import Organization, User
from apps.api.app.schemas.agent import (
    AgentCreate,
    AgentProxyRequest,
    AgentProxyResponse,
    AgentResponse,
    AgentSessionCreate,
    AgentSessionResponse,
)
from apps.api.app.services.agent_service import agent_service

router = APIRouter(prefix="/agents", tags=["AI Agent Access"])


@router.post("", response_model=AgentResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("agent:create"))])
async def create_agent(
    req: AgentCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Register an autonomous AI agent identity with scoping policies."""
    agent = await agent_service.create_agent(
        db=db,
        org_id=org.id,
        project_id=req.project_id,
        environment_id=req.environment_id,
        name=req.name,
        slug=req.slug,
        description=req.description,
        max_ttl_seconds=req.max_ttl_seconds,
        policy_schema=req.policy,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return agent


@router.get("", response_model=list[AgentResponse], dependencies=[Depends(require_permission("agent:read"))])
async def list_agents(
    project_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    """List registered AI agents for the organization."""
    return await agent_service.list_agents(db=db, org_id=org.id, project_id=project_id)


@router.get("/{agent_id}", response_model=AgentResponse, dependencies=[Depends(require_permission("agent:read"))])
async def get_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
):
    """Retrieve detailed agent identity and policy configuration."""
    return await agent_service.get_agent(db=db, org_id=org.id, agent_id=agent_id)


@router.post("/{agent_id}/sessions", response_model=AgentSessionResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("agent:create"))])
async def create_agent_session(
    agent_id: uuid.UUID,
    req: AgentSessionCreate,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Generate an ephemeral, scoped session token for an AI agent."""
    session, raw_token = await agent_service.create_session(
        db=db,
        org_id=org.id,
        agent_id=agent_id,
        ttl_seconds=req.ttl_seconds,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return AgentSessionResponse(
        session_id=session.id,
        agent_id=session.agent_id,
        token=raw_token,
        expires_at=session.expires_at,
        status=session.status,
    )


@router.post("/{agent_id}/sessions/{session_id}/revoke", dependencies=[Depends(require_permission("agent:create"))])
async def revoke_agent_session(
    agent_id: uuid.UUID,
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
):
    """Instantly revoke an active agent session token."""
    session = await agent_service.revoke_session(
        db=db,
        org_id=org.id,
        agent_id=agent_id,
        session_id=session_id,
        actor_id=user.id,
        actor_name=user.full_name,
    )
    return {"status": "revoked", "session_id": session.id}


@router.post("/proxy", response_model=AgentProxyResponse)
async def execute_agent_proxy_call(
    req: AgentProxyRequest,
    authorization: str | None = Header(None),
    x_agent_session: str | None = Header(None, alias="X-Agent-Session-Token"),
    db: AsyncSession = Depends(get_db),
):
    """
    AI Agent Out-of-Band Proxy Gateway.
    Authenticates via agent session token, enforces tool/domain policy,
    resolves {{ aegis:secret:<KEY> }} placeholders in-memory, and forwards the request.
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif x_agent_session:
        token = x_agent_session.strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent session token in Authorization Bearer or X-Agent-Session-Token header",
        )

    return await agent_service.execute_proxy_call(db=db, raw_session_token=token, req=req)
