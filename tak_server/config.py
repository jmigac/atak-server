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
    allow_password_auth: bool
    cert_auth_enabled: bool
    cert_auth_auto_provision: bool
    auth_token: Optional[str]
    tls_enabled: bool
    tls_require_client_cert: bool
    tls_ca_file: Optional[str]
    tls_ca_path: Optional[str]
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
        allow_password_auth=_read_bool("TAK_ALLOW_PASSWORD_AUTH", True),
        cert_auth_enabled=_read_bool("TAK_CERT_AUTH_ENABLED", False),
        cert_auth_auto_provision=_read_bool("TAK_CERT_AUTO_PROVISION", True),
        auth_token=os.getenv("TAK_AUTH_TOKEN"),
        tls_enabled=_read_bool("TAK_TLS_ENABLED", False),
        tls_require_client_cert=_read_bool("TAK_TLS_REQUIRE_CLIENT_CERT", False),
        tls_ca_file=os.getenv("TAK_TLS_CA_FILE"),
        tls_ca_path=os.getenv("TAK_TLS_CA_PATH"),
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
    if settings.tls_require_client_cert or settings.cert_auth_enabled:
        if not settings.tls_ca_file and not settings.tls_ca_path:
            raise ValueError(
                "Client certificate validation requires TAK_TLS_CA_FILE or TAK_TLS_CA_PATH"
            )
        context.load_verify_locations(cafile=settings.tls_ca_file, capath=settings.tls_ca_path)
        context.verify_mode = (
            ssl.CERT_REQUIRED if settings.tls_require_client_cert else ssl.CERT_OPTIONAL
        )
    else:
        context.verify_mode = ssl.CERT_NONE
    return context
