from fastapi import APIRouter

from apps.api.app.api.v1.auth import router as auth_router
from apps.api.app.api.v1.projects import router as projects_router
from apps.api.app.api.v1.secrets import router as secrets_router
from apps.api.app.api.v1.pki import router as pki_router
from apps.api.app.api.v1.kms import router as kms_router
from apps.api.app.api.v1.access import router as access_router
from apps.api.app.api.v1.audit import router as audit_router
from apps.api.app.api.v1.scanner import router as scanner_router
from apps.api.app.api.v1.integrations import router as integrations_router
from apps.api.app.api.v1.dynamic import router as dynamic_router
from apps.api.app.api.v1.health import router as health_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(projects_router)
api_router.include_router(secrets_router)
api_router.include_router(pki_router)
api_router.include_router(kms_router)
api_router.include_router(access_router)
api_router.include_router(audit_router)
api_router.include_router(scanner_router)
api_router.include_router(integrations_router)
api_router.include_router(dynamic_router)
