import csv
import hashlib
import io
import json
import uuid
from typing import Any

from sqlalchemy import asc, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.audit import AuditEvent

GENESIS_HASH = "GENESIS_HASH_000000000000000000000000000000000000000000000000000"  # 64 chars


class AuditService:
    @staticmethod
    def _compute_event_hash(
        prev_hash: str,
        org_id: str,
        project_id: str | None,
        actor_name: str,
        action: str,
        resource_type: str,
        resource_id: str | None,
        result: str,
        sanitized_meta: dict[str, Any],
    ) -> str:
        payload_to_hash = {
            "prev_hash": prev_hash,
            "org_id": str(org_id),
            "project_id": str(project_id) if project_id else None,
            "actor_name": actor_name,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "result": result,
            "metadata": sanitized_meta,
        }
        return hashlib.sha256(json.dumps(payload_to_hash, sort_keys=True).encode("utf-8")).hexdigest()

    @staticmethod
    async def log_event(
        db: AsyncSession,
        organization_id: uuid.UUID,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        project_id: uuid.UUID | None = None,
        actor_id: uuid.UUID | None = None,
        actor_name: str = "system",
        actor_type: str = "user",
        result: str = "success",
        request_id: str | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Create an append-only, tamper-evident audit event record."""
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id)
            .order_by(desc(AuditEvent.created_at), desc(AuditEvent.id))
            .limit(1)
        )
        result_exec = await db.execute(stmt)
        latest_event = result_exec.scalar_one_or_none()
        prev_hash = latest_event.event_hash if latest_event else GENESIS_HASH

        clean_metadata = metadata or {}
        # Strict sanitization: ensure no plaintext secret material exists in metadata
        sanitized_meta = {
            k: v for k, v in clean_metadata.items()
            if not any(sub in k.lower() for sub in ["secret", "password", "token", "key_material", "plaintext"])
        }

        event_hash = AuditService._compute_event_hash(
            prev_hash=prev_hash,
            org_id=str(organization_id),
            project_id=str(project_id) if project_id else None,
            actor_name=actor_name,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            sanitized_meta=sanitized_meta,
        )

        event = AuditEvent(
            organization_id=organization_id,
            project_id=project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            actor_type=actor_type,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
            metadata_json=sanitized_meta,
            prev_event_hash=prev_hash,
            event_hash=event_hash,
        )
        db.add(event)
        await db.flush()
        return event

    @staticmethod
    async def verify_chain(db: AsyncSession, organization_id: uuid.UUID) -> dict[str, Any]:
        """Cryptographically verify the SHA-256 hash chain for an organization."""
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id)
            .order_by(asc(AuditEvent.created_at), asc(AuditEvent.id))
        )
        res = await db.execute(stmt)
        events = res.scalars().all()

        if not events:
            return {"valid": True, "total_events": 0, "message": "Genesis state: no audit events recorded yet."}

        expected_prev_hash = GENESIS_HASH
        for idx, event in enumerate(events):
            # 1. Check prev_hash linkage
            if event.prev_event_hash != expected_prev_hash:
                return {
                    "valid": False,
                    "total_events": len(events),
                    "corrupted_event_index": idx,
                    "corrupted_event_id": str(event.id),
                    "error": f"Hash chain break: Expected prev_hash {expected_prev_hash} but found {event.prev_event_hash}",
                }

            # 2. Check event_hash integrity
            recalculated_hash = AuditService._compute_event_hash(
                prev_hash=event.prev_event_hash,
                org_id=str(event.organization_id),
                project_id=str(event.project_id) if event.project_id else None,
                actor_name=event.actor_name,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                result=event.result,
                sanitized_meta=event.metadata_json or {},
            )

            if event.event_hash != recalculated_hash:
                return {
                    "valid": False,
                    "total_events": len(events),
                    "corrupted_event_index": idx,
                    "corrupted_event_id": str(event.id),
                    "error": f"Tampered event data: Expected event_hash {recalculated_hash} but found {event.event_hash}",
                }

            expected_prev_hash = event.event_hash

        return {
            "valid": True,
            "total_events": len(events),
            "latest_event_hash": expected_prev_hash,
            "message": f"Cryptographic chain intact. Verified {len(events)} tamper-evident audit events.",
        }

    @staticmethod
    async def export_events(db: AsyncSession, organization_id: uuid.UUID, format_type: str = "json") -> str:
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id)
            .order_by(desc(AuditEvent.created_at))
        )
        res = await db.execute(stmt)
        events = res.scalars().all()

        if format_type == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["timestamp", "action", "actor_name", "actor_type", "resource_type", "resource_id", "result", "event_hash"])
            for e in events:
                writer.writerow([e.created_at.isoformat(), e.action, e.actor_name, e.actor_type, e.resource_type, e.resource_id, e.result, e.event_hash])
            return output.getvalue()
        elif format_type == "jsonl":
            lines = [
                json.dumps({
                    "id": str(e.id),
                    "timestamp": e.created_at.isoformat(),
                    "action": e.action,
                    "actor_name": e.actor_name,
                    "actor_type": e.actor_type,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "result": e.result,
                    "event_hash": e.event_hash,
                    "prev_event_hash": e.prev_event_hash,
                    "metadata": e.metadata_json,
                })
                for e in events
            ]
            return "\n".join(lines)
        elif format_type == "syslog":
            syslog_lines = []
            for e in events:
                meta_str = " ".join(f'{k}="{v}"' for k, v in (e.metadata_json or {}).items())
                syslog_lines.append(
                    f"<134>1 {e.created_at.isoformat()} aegisvault security-audit - - [aegis@32473 action=\"{e.action}\" actor=\"{e.actor_name}\" result=\"{e.result}\" resource=\"{e.resource_type}:{e.resource_id}\" hash=\"{e.event_hash}\" {meta_str}] Audit event recorded"
                )
            return "\n".join(syslog_lines)
        else:
            export_list = [
                {
                    "id": str(e.id),
                    "timestamp": e.created_at.isoformat(),
                    "action": e.action,
                    "actor_name": e.actor_name,
                    "actor_type": e.actor_type,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "result": e.result,
                    "event_hash": e.event_hash,
                    "prev_event_hash": e.prev_event_hash,
                    "metadata": e.metadata_json,
                }
                for e in events
            ]
            return json.dumps(export_list, indent=2)


audit_service = AuditService()
