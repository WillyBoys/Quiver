"""Runtime settings, read from QUIVER_* environment variables.

Secrets are never passed as values: settings point at files (Docker secrets), and the files
are read on demand. A missing or empty secret file is a startup error, not a silent default.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class SecretFileError(RuntimeError):
    pass


def read_secret_file(path: Path | None, name: str) -> SecretStr:
    if path is None:
        raise SecretFileError(f"{name} is not configured (set QUIVER_{name.upper()}_FILE)")
    try:
        value = path.read_text().strip()
    except OSError as exc:
        raise SecretFileError(f"cannot read {name} from {path}: {exc.strerror}") from exc
    if not value:
        raise SecretFileError(f"{name} file {path} is empty")
    return SecretStr(value)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="QUIVER_")

    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "quiver"
    db_user: str = "quiver"
    db_password_file: Path | None = None
    # Full URL override. Intended for tests and CI only; normal deployments use the fields
    # above so the password stays in a secret file.
    database_url: SecretStr | None = None

    secret_key_file: Path | None = None

    # Browser origins allowed to call the API with credentials (the dashboard).
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://127.0.0.1:3000", "http://localhost:3000"]
    )
    session_ttl_hours: int = Field(default=12, ge=1, le=24 * 7)
    # The stack is reached over 127.0.0.1 or an SSH tunnel (plain HTTP), so cookies are not
    # marked Secure by default. Set to true when serving the dashboard over HTTPS.
    cookie_secure: bool = False
    # Interactive API docs (/docs, /redoc, /openapi.json). Off by default: they map the
    # whole API without requiring a login. Enable for local development only.
    api_docs: bool = False

    def db_url(self) -> URL | str:
        if self.database_url is not None:
            return self.database_url.get_secret_value()
        return URL.create(
            "postgresql+asyncpg",
            username=self.db_user,
            password=read_secret_file(self.db_password_file, "db_password").get_secret_value(),
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        )

    def secret_key(self) -> SecretStr:
        return read_secret_file(self.secret_key_file, "secret_key")


@lru_cache
def get_settings() -> Settings:
    return Settings()
