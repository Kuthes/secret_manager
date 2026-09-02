import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.security import get_password_hash
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership, Project, Environment, ProjectMembership
from apps.api.app.models.pam import AccessResource, AccessRequest
from apps.api.app.models.scanner import ScannerRepository, ScanJob, ScanFinding
from apps.api.app.services.secret_service import secret_service
from apps.api.app.services.pki_service import pki_service
from apps.api.app.services.kms_service import kms_service
from apps.api.app.services.audit_service import audit_service


class SeedService:
    @staticmethod
    async def seed_demo_data(db: AsyncSession) -> None:
        # Check if already seeded
        stmt = select(User).where(User.email == "demo@aegisvault.local")
        res = await db.execute(stmt)
        if res.scalar_one_or_none():
            return  # Already seeded

        # 1. Create Demo User
        user = User(
            email="demo@aegisvault.local",
            hashed_password=get_password_hash("AegisDemo2026!"),
            full_name="Saurabh Kuthe",
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        await db.flush()

        # 2. Create Organization
        org = Organization(
            name="Acme Cloud",
            slug="acme-cloud",
        )
        db.add(org)
        await db.flush()

        # 3. Create Role & Membership
        owner_role = Role(
            organization_id=org.id,
            name="Organization Owner",
            slug="owner",
            description="Full organization privileges",
            is_system=True,
        )
        db.add(owner_role)
        await db.flush()

        membership = OrganizationMembership(
            organization_id=org.id,
            user_id=user.id,
            role_id=owner_role.id,
        )
        db.add(membership)

        # 4. Create Project & Environments
        project = Project(
            organization_id=org.id,
            name="Payments API",
            slug="payments-api",
            description="Core payment processing microservice and webhooks",
        )
        db.add(project)
        await db.flush()

        env_dev = Environment(project_id=project.id, name="Development", slug="development", position=0)
        env_stage = Environment(project_id=project.id, name="Staging", slug="staging", position=1)
        env_prod = Environment(project_id=project.id, name="Production", slug="production", position=2)
        db.add_all([env_dev, env_stage, env_prod])
        await db.flush()

        proj_membership = ProjectMembership(
            project_id=project.id,
            user_id=user.id,
            role_id=owner_role.id,
        )
        db.add(proj_membership)

        # 5. Seed Envelope-Encrypted Secrets in Production
        demo_secrets = [
            ("DATABASE_URL", "postgresql://aegis:demo@postgres:5432/app", "/backend", "Production PostgreSQL connection string"),
            ("STRIPE_SECRET_KEY", "TESTONLY_sk_test_51Nq8f94k18a93n7Xk", "/payments", "Stripe API live billing secret"),
            ("REDIS_URL", "redis://cache:6379/0", "/backend", "Cache cluster URL"),
            ("JWT_SIGNING_KEY", "aegis_5tQ8w910fka919wD2", "/auth", "Access token signature key"),
            ("OPENAI_API_KEY", "sk-proj-xJ2941kfa09429Np", "/ai", "AI assistant inference token"),
        ]

        for key, val, path, comment in demo_secrets:
            await secret_service.create_secret(
                db=db,
                project_id=project.id,
                environment_id=env_prod.id,
                key=key,
                value=val,
                path=path,
                comment=comment,
                actor_id=user.id,
                actor_name=user.full_name,
            )

        # 6. Seed PKI CAs & Certificates
        root_ca = await pki_service.create_ca(
            db=db,
            organization_id=org.id,
            name="Acme Root CA G1",
            common_name="Acme Root Certificate Authority",
            ca_type="root",
            validity_days=3650,
            actor_id=user.id,
            actor_name=user.full_name,
        )

        cert_1, _ = await pki_service.issue_certificate(
            db=db,
            ca_id=root_ca.id,
            common_name="api.prod.acme.dev",
            san_dns_names=["api.prod.acme.dev", "payments.prod.acme.dev"],
            validity_days=90,
            actor_id=user.id,
            actor_name=user.full_name,
        )

        # 7. Seed Managed KMS Keys
        await kms_service.create_key(
            db=db,
            organization_id=org.id,
            project_id=project.id,
            name="payments-master",
            algorithm="AES-256-GCM",
            key_usage="ENCRYPT_DECRYPT",
            actor_id=user.id,
            actor_name=user.full_name,
        )
        await kms_service.create_key(
            db=db,
            organization_id=org.id,
            project_id=project.id,
            name="session-signing",
            algorithm="Ed25519",
            key_usage="SIGN_VERIFY",
            actor_id=user.id,
            actor_name=user.full_name,
        )

        # 8. Seed PAM Resource & Request
        pam_res = AccessResource(
            organization_id=org.id,
            project_id=project.id,
            name="Production PostgreSQL Console",
            resource_type="database",
            resource_identifier="postgres://prod-db.acme.internal:5432/app",
            max_duration_seconds=7200,
        )
        db.add(pam_res)
        await db.flush()

        req = AccessRequest(
            resource_id=pam_res.id,
            requester_id=user.id,
            justification="Investigate transaction timeout on payment webhook handler",
            duration_seconds=3600,
            status="pending",
        )
        db.add(req)

        # 9. Seed Scanner Findings
        scan_repo = ScannerRepository(
            project_id=project.id,
            repo_url="github.com/acme/payments-api",
            default_branch="main",
            status="protected",
        )
        db.add(scan_repo)
        await db.flush()

        scan_job = ScanJob(
            repository_id=scan_repo.id,
            commit_sha="a7b8c9d0",
            status="completed",
            findings_count=1,
        )
        db.add(scan_job)
        await db.flush()

        scan_finding = ScanFinding(
            job_id=scan_job.id,
            rule_id="stripe-api-key",
            file_path="src/config/billing.ts",
            line_number=14,
            secret_fingerprint="b4c5d6e7f8a91011121314151617181920212223242526272829303132333435",
            redacted_preview="TESTONLY_sk_test_••••••••7Xk",
            severity="critical",
            status="open",
        )
        db.add(scan_finding)

        # 10. Seed Initial Activity Audit Events
        await audit_service.log_event(
            db=db,
            organization_id=org.id,
            project_id=project.id,
            actor_id=user.id,
            actor_name="Rotation bot",
            action="secret.rotate",
            resource_type="secret",
            resource_id="STRIPE_SECRET_KEY",
            metadata={"detail": "STRIPE_SECRET_KEY rotated automatically"},
        )
        await audit_service.log_event(
            db=db,
            organization_id=org.id,
            project_id=project.id,
            actor_id=user.id,
            actor_name=user.full_name,
            action="certificate.issue",
            resource_type="certificate",
            resource_id="api.prod.acme.dev",
            metadata={"detail": "api.prod.acme.dev · 90-day validity"},
        )

        await db.commit()


seed_service = SeedService()
