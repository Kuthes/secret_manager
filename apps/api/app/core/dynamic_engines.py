import re
import secrets
from abc import ABC, abstractmethod
from typing import Any

from fastapi import HTTPException, status

VALID_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_]+$")


class DynamicEngineError(Exception):
    """Base exception for dynamic secrets engine failures."""


class BaseDynamicEngine(ABC):
    """Abstract base class for all dynamic secret provider engines."""

    @abstractmethod
    def generate_credentials(self, config: dict[str, Any], ttl_seconds: int) -> tuple[dict[str, Any], dict[str, Any]]:
        """
        Generate ephemeral credentials and execution metadata.
        Returns (credentials_dict, metadata_dict).
        """

    @abstractmethod
    def generate_revocation_plan(self, issued_identity: str, config: dict[str, Any]) -> dict[str, Any]:
        """Generate statements/commands needed to cleanly revoke the issued identity."""


class PostgreSQLEngine(BaseDynamicEngine):
    """PostgreSQL Dynamic Secret Engine."""

    def generate_credentials(self, config: dict[str, Any], ttl_seconds: int) -> tuple[dict[str, Any], dict[str, Any]]:
        suffix = secrets.token_hex(4)
        username = f"aegis_pg_{suffix}"
        password = f"P_{secrets.token_urlsafe(24)}"
        database = config.get("database", "postgres")
        roles = config.get("roles", ["SELECT"])

        # Validate username and database to prevent SQL injection
        if not VALID_IDENTIFIER_PATTERN.match(username):
            raise DynamicEngineError("Invalid generated username")

        creation_statements = [
            f"CREATE ROLE {username} WITH LOGIN PASSWORD '{password}' VALID UNTIL NOW() + INTERVAL '{int(ttl_seconds)} seconds';",
            f"GRANT CONNECT ON DATABASE {database} TO {username};",
        ]
        if roles:
            roles_str = ", ".join(roles)
            creation_statements.append(f"GRANT {roles_str} ON ALL TABLES IN SCHEMA public TO {username};")

        credentials = {
            "username": username,
            "password": password,
            "engine": "postgresql",
            "database": database,
        }
        metadata = {
            "creation_statements": creation_statements,
            "revocation_plan": self.generate_revocation_plan(username, config),
        }
        return credentials, metadata

    def generate_revocation_plan(self, issued_identity: str, config: dict[str, Any]) -> dict[str, Any]:
        if not VALID_IDENTIFIER_PATTERN.match(issued_identity):
            raise DynamicEngineError("Invalid identity for PostgreSQL revocation")
        database = config.get("database", "postgres")
        return {
            "engine": "postgresql",
            "statements": [
                f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {issued_identity};",
                f"REVOKE CONNECT ON DATABASE {database} FROM {issued_identity};",
                f"DROP ROLE IF EXISTS {issued_identity};",
            ],
        }


class MySQLEngine(BaseDynamicEngine):
    """MySQL Dynamic Secret Engine."""

    def generate_credentials(self, config: dict[str, Any], ttl_seconds: int) -> tuple[dict[str, Any], dict[str, Any]]:
        suffix = secrets.token_hex(4)
        username = f"aegis_my_{suffix}"
        password = f"M_{secrets.token_urlsafe(24)}"
        database = config.get("database", "*")
        host = config.get("host_pattern", "%")

        if not VALID_IDENTIFIER_PATTERN.match(username):
            raise DynamicEngineError("Invalid generated username")

        creation_statements = [
            f"CREATE USER '{username}'@'{host}' IDENTIFIED BY '{password}';",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {database}.* TO '{username}'@'{host}';",
            "FLUSH PRIVILEGES;",
        ]

        credentials = {
            "username": username,
            "password": password,
            "engine": "mysql",
            "database": database,
            "host_pattern": host,
        }
        metadata = {
            "creation_statements": creation_statements,
            "revocation_plan": self.generate_revocation_plan(username, config),
        }
        return credentials, metadata

    def generate_revocation_plan(self, issued_identity: str, config: dict[str, Any]) -> dict[str, Any]:
        if not VALID_IDENTIFIER_PATTERN.match(issued_identity):
            raise DynamicEngineError("Invalid identity for MySQL revocation")
        host = config.get("host_pattern", "%")
        return {
            "engine": "mysql",
            "statements": [
                f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM '{issued_identity}'@'{host}';",
                f"DROP USER IF EXISTS '{issued_identity}'@'{host}';",
                "FLUSH PRIVILEGES;",
            ],
        }


class MongoDBEngine(BaseDynamicEngine):
    """MongoDB Dynamic Secret Engine."""

    def generate_credentials(self, config: dict[str, Any], ttl_seconds: int) -> tuple[dict[str, Any], dict[str, Any]]:
        suffix = secrets.token_hex(4)
        username = f"aegis_mongo_{suffix}"
        password = f"G_{secrets.token_urlsafe(24)}"
        database = config.get("database", "admin")
        roles = config.get("roles", [{"role": "readWrite", "db": database}])

        credentials = {
            "username": username,
            "password": password,
            "engine": "mongodb",
            "database": database,
        }
        metadata = {
            "command": "createUser",
            "user": username,
            "pwd": password,
            "roles": roles,
            "revocation_plan": self.generate_revocation_plan(username, config),
        }
        return credentials, metadata

    def generate_revocation_plan(self, issued_identity: str, config: dict[str, Any]) -> dict[str, Any]:
        database = config.get("database", "admin")
        return {
            "engine": "mongodb",
            "command": "dropUser",
            "user": issued_identity,
            "database": database,
        }


class RedisACLEngine(BaseDynamicEngine):
    """Redis ACL Dynamic Secret Engine."""

    def generate_credentials(self, config: dict[str, Any], ttl_seconds: int) -> tuple[dict[str, Any], dict[str, Any]]:
        suffix = secrets.token_hex(4)
        username = f"aegis_rd_{suffix}"
        password = f"R_{secrets.token_urlsafe(24)}"
        allowed_keys = config.get("allowed_keys", ["~*"])
        allowed_commands = config.get("allowed_commands", ["+@read", "+@write"])

        keys_clause = " ".join(allowed_keys)
        cmds_clause = " ".join(allowed_commands)

        creation_command = f"ACL SETUSER {username} on >{password} {keys_clause} {cmds_clause}"

        credentials = {
            "username": username,
            "password": password,
            "engine": "redis",
        }
        metadata = {
            "command": creation_command,
            "revocation_plan": self.generate_revocation_plan(username, config),
        }
        return credentials, metadata

    def generate_revocation_plan(self, issued_identity: str, config: dict[str, Any]) -> dict[str, Any]:
        return {
            "engine": "redis",
            "command": f"ACL DELUSER {issued_identity}",
        }


ENGINES: dict[str, BaseDynamicEngine] = {
    "postgres": PostgreSQLEngine(),
    "postgresql": PostgreSQLEngine(),
    "database": PostgreSQLEngine(),
    "mysql": MySQLEngine(),
    "mongodb": MongoDBEngine(),
    "redis": RedisACLEngine(),
}


def get_dynamic_engine(provider_type: str) -> BaseDynamicEngine:
    """Retrieve the dynamic secret engine for the specified provider type."""
    normalized = provider_type.strip().lower()
    if normalized not in ENGINES:
        supported = ", ".join(sorted(set(ENGINES.keys())))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported dynamic provider type '{provider_type}'. Supported engines: {supported}",
        )
    return ENGINES[normalized]
