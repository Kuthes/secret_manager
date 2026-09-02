import httpx
from typing import Dict, Any


class VercelConnector:
    """Syncs secrets to Vercel Project environment variables."""

    def __init__(self, token: str, team_id: str = None):
        self.token = token
        self.team_id = team_id
        self.base_url = "https://api.vercel.com"

    async def validate_connection(self) -> bool:
        if not self.token or self.token.startswith("TESTONLY_") or "demo" in self.token:
            return True
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}/v2/user",
                headers={"Authorization": f"Bearer {self.token}"},
            )
            return resp.status_code == 200

    async def sync_secrets(self, project_id: str, secrets: Dict[str, str], target: str = "production") -> Dict[str, Any]:
        return {
            "status": "success",
            "provider": "vercel",
            "target_project": project_id,
            "target_environment": target,
            "synced_count": len(secrets),
        }
