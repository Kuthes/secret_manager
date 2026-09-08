import hashlib
import json
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.api.loaders import get_owned_environment
from apps.api.app.core.rate_limiter import check_rate_limit
from apps.api.app.core.ssrf import SSRFProtectionError, validate_safe_url
from apps.api.app.models.agent import AgentIdentity, AgentPolicy, AgentSession
from apps.api.app.models.secret import Secret
from apps.api.app.schemas.agent import (
    AgentPolicySchema,
    AgentProxyRequest,
    AgentProxyResponse,
)
from apps.api.app.services.audit_service import audit_service
from apps.api.app.services.secret_service import secret_service

SECRET_PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*aegis:secret:([A-Za-z0-9_]+)\s*\}\}")


class AgentService:
    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def create_agent(
        self,
        db: AsyncSession,
        org_id: uuid.UUID,
        project_id: uuid.UUID,
        environment_id: uuid.UUID,
        name: str,
        slug: str,
        description: str | None,
        max_ttl_seconds: int,
        policy_schema: AgentPolicySchema,
        actor_id: uuid.UUID | None = None,
        actor_name: str | None = None,
    ) -> AgentIdentity:
        await get_owned_environment(db=db, environment_id=environment_id, project_id=project_id, organization_id=org_id)

        agent = AgentIdentity(
            organization_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            name=name,
            slug=slug.lower().strip(),
            description=description,
            max_ttl_seconds=max_ttl_seconds,
            is_active=True,
        )
        db.add(agent)
        await db.flush()

        policy = AgentPolicy(
            agent_id=agent.id,
            allowed_tools=policy_schema.allowed_tools,
            allowed_domains=policy_schema.allowed_domains,
            max_requests_per_minute=policy_schema.max_requests_per_minute,
            require_justification=policy_schema.require_justification,
        )
        db.add(policy)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=org_id,
            project_id=project_id,
            actor_id=actor_id,
            actor_name=actor_name or "System",
            action="agent.create",
            resource_type="agent",
            resource_id=str(agent.id),
            metadata={"name": name, "slug": slug, "allowed_tools": policy_schema.allowed_tools},
        )

        stmt = (
            select(AgentIdentity)
            .options(selectinload(AgentIdentity.policy))
            .where(AgentIdentity.id == agent.id)
        )
        res = await db.execute(stmt)
        return res.scalar_one()

    async def list_agents(
        self,
        db: AsyncSession,
        org_id: uuid.UUID,
        project_id: uuid.UUID | None = None,
    ) -> list[AgentIdentity]:
        conditions = [
            AgentIdentity.organization_id == org_id,
            AgentIdentity.is_deleted == False,
        ]
        if project_id:
            conditions.append(AgentIdentity.project_id == project_id)

        stmt = (
            select(AgentIdentity)
            .options(selectinload(AgentIdentity.policy))
            .where(and_(*conditions))
            .order_by(AgentIdentity.name)
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())

    async def get_agent(
        self,
        db: AsyncSession,
        org_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> AgentIdentity:
        stmt = (
            select(AgentIdentity)
            .options(selectinload(AgentIdentity.policy))
            .where(
                and_(
                    AgentIdentity.id == agent_id,
                    AgentIdentity.organization_id == org_id,
                    AgentIdentity.is_deleted == False,
                )
            )
        )
        res = await db.execute(stmt)
        agent = res.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent identity not found")
        return agent

    async def create_session(
        self,
        db: AsyncSession,
        org_id: uuid.UUID,
        agent_id: uuid.UUID,
        ttl_seconds: int | None = None,
        actor_id: uuid.UUID | None = None,
        actor_name: str | None = None,
    ) -> tuple[AgentSession, str]:
        agent = await self.get_agent(db=db, org_id=org_id, agent_id=agent_id)
        if not agent.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Agent is deactivated")

        ttl = ttl_seconds if ttl_seconds is not None else agent.max_ttl_seconds
        ttl = min(ttl, agent.max_ttl_seconds)

        raw_token = f"aegis_ag_sess_{uuid.uuid4().hex}_{secrets.token_hex(24)}"
        token_hash = self._hash_token(raw_token)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl)

        session = AgentSession(
            agent_id=agent.id,
            session_token_hash=token_hash,
            status="active",
            expires_at=expires_at,
        )
        db.add(session)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=org_id,
            project_id=agent.project_id,
            actor_id=actor_id,
            actor_name=actor_name or "System",
            action="agent.session_create",
            resource_type="agent_session",
            resource_id=str(session.id),
            metadata={"agent_id": str(agent.id), "expires_at": expires_at.isoformat(), "ttl_seconds": ttl},
        )
        return session, raw_token

    async def revoke_session(
        self,
        db: AsyncSession,
        org_id: uuid.UUID,
        agent_id: uuid.UUID,
        session_id: uuid.UUID,
        actor_id: uuid.UUID | None = None,
        actor_name: str | None = None,
    ) -> AgentSession:
        agent = await self.get_agent(db=db, org_id=org_id, agent_id=agent_id)
        stmt = select(AgentSession).where(
            and_(
                AgentSession.id == session_id,
                AgentSession.agent_id == agent.id,
            )
        )
        res = await db.execute(stmt)
        session = res.scalar_one_or_none()
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent session not found")

        session.status = "revoked"
        session.revoked_at = datetime.now(timezone.utc)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=org_id,
            project_id=agent.project_id,
            actor_id=actor_id,
            actor_name=actor_name or "System",
            action="agent.session_revoke",
            resource_type="agent_session",
            resource_id=str(session.id),
            metadata={"agent_id": str(agent.id)},
        )
        return session

    async def execute_proxy_call(
        self,
        db: AsyncSession,
        raw_session_token: str,
        req: AgentProxyRequest,
    ) -> AgentProxyResponse:
        token_hash = self._hash_token(raw_session_token)
        now = datetime.now(timezone.utc)

        stmt = (
            select(AgentSession)
            .options(
                selectinload(AgentSession.agent).selectinload(AgentIdentity.policy),
            )
            .where(
                and_(
                    AgentSession.session_token_hash == token_hash,
                    AgentSession.status == "active",
                )
            )
        )
        res = await db.execute(stmt)
        session = res.scalar_one_or_none()
        if not session:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired agent session token")

        exp = session.expires_at if session.expires_at.tzinfo else session.expires_at.replace(tzinfo=timezone.utc)
        if exp <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired agent session token")

        agent = session.agent
        if not agent.is_active or agent.is_deleted:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent identity is disabled")

        policy = agent.policy
        # 1. SSRF Validation
        try:
            validate_safe_url(req.url, allow_private=False)
        except SSRFProtectionError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"SSRF Protection: {e!s}")

        parsed_url = urlparse(req.url)
        hostname = (parsed_url.hostname or "").lower()

        # 2. Policy: Domain allowlist enforcement
        if policy and policy.allowed_domains:
            allowed = any(hostname == d.lower() or hostname.endswith("." + d.lower()) for d in policy.allowed_domains)
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Destination domain '{hostname}' is not authorized by agent policy",
                )

        # 3. Policy: Tool allowlist enforcement
        if policy and policy.allowed_tools and req.tool_name and req.tool_name not in policy.allowed_tools:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Tool '{req.tool_name}' is not authorized by agent policy",
            )

        # 4. Rate limiting per agent
        limit = policy.max_requests_per_minute if policy else 60
        await check_rate_limit(f"agent_proxy:{agent.id}", max_requests=limit, window_seconds=60)

        # 5. In-Memory Secret Substitution
        # Recursively substitute {{ aegis:secret:<KEY> }} in headers and payload
        headers_to_send = dict(req.headers)
        body_to_send = req.body

        # Helper to replace secret placeholders in a string
        async def resolve_placeholders(text: str) -> str:
            matches = SECRET_PLACEHOLDER_PATTERN.findall(text)
            if not matches:
                return text
            
            result = text
            for secret_key in set(matches):
                # Fetch secret in agent's project and environment
                stmt_sec = select(Secret).where(
                    and_(
                        Secret.project_id == agent.project_id,
                        Secret.environment_id == agent.environment_id,
                        Secret.key == secret_key.strip().upper(),
                        Secret.is_deleted.is_(False),
                    )
                )
                r_sec = await db.execute(stmt_sec)
                sec_obj = r_sec.scalar_one_or_none()
                if not sec_obj:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Secret '{secret_key}' required by agent placeholder not found in scope",
                    )
                _, plain_val = await secret_service.reveal_secret(
                    db=db,
                    secret_id=sec_obj.id,
                    actor_id=agent.id,
                    actor_name=f"Agent:{agent.name}",
                    justification=req.justification or "AI Agent Proxy Execution",
                )
                pattern = re.compile(r"\{\{\s*aegis:secret:" + re.escape(secret_key) + r"\s*\}\}")
                result = pattern.sub(plain_val, result)
            return result

        # Substitute in headers
        for h_key, h_val in list(headers_to_send.items()):
            if isinstance(h_val, str) and "{{" in h_val:
                headers_to_send[h_key] = await resolve_placeholders(h_val)

        # Substitute in body if string or JSON
        if isinstance(body_to_send, str) and "{{" in body_to_send:
            body_to_send = await resolve_placeholders(body_to_send)
        elif isinstance(body_to_send, dict):
            body_json = json.dumps(body_to_send)
            if "{{" in body_json:
                resolved_json = await resolve_placeholders(body_json)
                body_to_send = json.loads(resolved_json)

        # 6. Execute outbound call
        start_time = time.perf_counter()
        req_id = str(uuid.uuid4())
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                if isinstance(body_to_send, dict):
                    resp = await client.request(
                        method=req.method,
                        url=req.url,
                        headers=headers_to_send,
                        json=body_to_send,
                    )
                else:
                    resp = await client.request(
                        method=req.method,
                        url=req.url,
                        headers=headers_to_send,
                        content=body_to_send,
                    )
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                try:
                    resp_data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    resp_data = resp.text

                # Log proxy audit event
                await audit_service.log_event(
                    db=db,
                    organization_id=agent.organization_id,
                    project_id=agent.project_id,
                    actor_id=agent.id,
                    actor_name=f"Agent:{agent.name}",
                    action="agent.proxy_call",
                    resource_type="agent_proxy",
                    resource_id=str(session.id),
                    metadata={
                        "tool_name": req.tool_name,
                        "destination_host": hostname,
                        "method": req.method,
                        "status_code": resp.status_code,
                        "latency_ms": latency_ms,
                    },
                )

                return AgentProxyResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    data=resp_data,
                    latency_ms=latency_ms,
                    request_id=req_id,
                )
        except httpx.RequestError as e:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Agent proxy upstream connection failed: {e!s}",
            )


agent_service = AgentService()
