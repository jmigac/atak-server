from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from typing import Optional


def _read_bool(key: str, default: bool = False) -> bool:
    value = os.getenv(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _read_int(key: str, default: int) -> int:
    value = os.getenv(key)
    if value is None:
        return default
    return int(value)


@dataclass(frozen=True)
class Settings:
    bind_host: str
    cot_port: int
    admin_port: int
    idle_timeout_seconds: int
    queue_size: int
    db_path: str
    data_dir: str
    default_group_name: str
    bootstrap_admin_username: str
    bootstrap_admin_password: str
    require_client_auth: bool
    auth_token: Optional[str]
    tls_enabled: bool
    tls_cert_file: Optional[str]
    tls_key_file: Optional[str]


def load_settings() -> Settings:
    return Settings(
        bind_host=os.getenv("TAK_BIND_HOST", "0.0.0.0"),
        cot_port=_read_int("TAK_COT_PORT", 8087),
        admin_port=_read_int("TAK_ADMIN_PORT", 8088),
        idle_timeout_seconds=_read_int("TAK_IDLE_TIMEOUT_SECONDS", 120),
        queue_size=_read_int("TAK_QUEUE_SIZE", 500),
        db_path=os.getenv("TAK_DB_PATH", "/app/data/tak_server.db"),
        data_dir=os.getenv("TAK_DATA_DIR", "/app/data"),
        default_group_name=os.getenv("TAK_DEFAULT_GROUP_NAME", "default"),
        bootstrap_admin_username=os.getenv("TAK_BOOTSTRAP_ADMIN_USERNAME", "admin"),
        bootstrap_admin_password=os.getenv("TAK_BOOTSTRAP_ADMIN_PASSWORD", "admin12345"),
        require_client_auth=_read_bool("TAK_REQUIRE_CLIENT_AUTH", True),
        auth_token=os.getenv("TAK_AUTH_TOKEN"),
        tls_enabled=_read_bool("TAK_TLS_ENABLED", False),
        tls_cert_file=os.getenv("TAK_TLS_CERT_FILE"),
        tls_key_file=os.getenv("TAK_TLS_KEY_FILE"),
    )


def build_tls_context(settings: Settings) -> Optional[ssl.SSLContext]:
    if not settings.tls_enabled:
        return None
    if not settings.tls_cert_file or not settings.tls_key_file:
        raise ValueError(
            "TLS is enabled but TAK_TLS_CERT_FILE or TAK_TLS_KEY_FILE is missing"
        )

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=settings.tls_cert_file, keyfile=settings.tls_key_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
