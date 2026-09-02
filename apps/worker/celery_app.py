from celery import Celery
from celery.schedules import crontab
from apps.api.app.core.config import settings

celery_app = Celery(
    "aegisvault_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "rotate-scheduled-secrets-every-5-mins": {
            "task": "apps.worker.tasks.rotate_scheduled_secrets",
            "schedule": crontab(minute="*/5"),
        },
        "revoke-expired-leases-every-minute": {
            "task": "apps.worker.tasks.revoke_expired_leases",
            "schedule": crontab(minute="*"),
        },
        "check-certificate-expirations-daily": {
            "task": "apps.worker.tasks.monitor_certificate_expiry",
            "schedule": crontab(hour="1", minute="0"),
        },
    },
)
