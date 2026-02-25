from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from tak_server.config import Settings
from tak_server.datapackage_builder import (
    ConnectionDataPackageRequest,
    build_connection_datapackage_zip,
)
from tak_server.qr_utils import render_qr_png
from tak_server.repository import Repository, UserIdentity


@dataclass(frozen=True)
class EnrollRequest:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes


def _http_reason(status: int) -> str:
    reasons = {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        405: "Method Not Allowed",
    }
    return reasons.get(status, "OK")


def _to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class EnrollmentApi:
    def __init__(self, settings: Settings, repository: Repository) -> None:
        self._settings = settings
        self._repository = repository

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request = await self._read_request(reader)
            if request is None:
                writer.close()
                await writer.wait_closed()
                return
            await self._dispatch(request, writer)
        except Exception:
            await self._write_json(writer, 400, {"error": "bad request"})
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

    async def _read_request(self, reader: asyncio.StreamReader) -> Optional[EnrollRequest]:
        try:
            raw_headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        except Exception:
            return None

        lines = raw_headers.decode("utf-8", errors="ignore").split("\r\n")
        if not lines or len(lines[0].split(" ")) < 2:
            return None
        first = lines[0].split(" ")
        method = first[0].upper()
        target = first[1]

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", maxsplit=1)
            headers[key.strip().lower()] = value.strip()

        try:
            content_length = int(headers.get("content-length", "0") or "0")
        except ValueError:
            return None

        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(reader.readexactly(content_length), timeout=10)

        parsed = urlparse(target)
        return EnrollRequest(
            method=method,
            path=parsed.path,
            query=parse_qs(parsed.query),
            headers=headers,
            body=body,
        )

    def _auth_user(self, request: EnrollRequest) -> Optional[UserIdentity]:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("basic "):
            return None
        encoded = auth.split(" ", maxsplit=1)[1]
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return None
        if ":" not in decoded:
            return None
        username, password = decoded.split(":", maxsplit=1)
        return self._repository.authenticate_user(username, password)

    def _host_for_bundle(self, request: EnrollRequest) -> str:
        if self._settings.public_host:
            return self._settings.public_host
        host_header = request.headers.get("host", "")
        host = host_header.split(":", maxsplit=1)[0].strip()
        return host or "localhost"

    def _base_url(self, request: EnrollRequest) -> str:
        host = self._host_for_bundle(request)
        if self._settings.public_host:
            scheme = "https" if self._settings.tls_enabled else "http"
            return f"{scheme}://{host}:{self._settings.enroll_port}"
        proto = request.headers.get("x-forwarded-proto")
        if proto:
            scheme = proto.split(",", maxsplit=1)[0].strip().lower()
        else:
            scheme = "https" if self._settings.tls_enabled else "http"
        return f"{scheme}://{host}:{self._settings.enroll_port}"

    def _truststore_bytes(self) -> bytes | None:
        path = self._settings.enroll_truststore_p12_file
        if not path:
            return None
        file_path = Path(path)
        if not file_path.exists():
            return None
        return file_path.read_bytes()

    def _build_connection_package(
        self,
        *,
        request: EnrollRequest,
        username: str,
        mode: str,
        use_tls: bool,
        lets_encrypt: bool,
        zip_name: str,
    ) -> bytes:
        truststore = self._truststore_bytes()
        package = build_connection_datapackage_zip(
            ConnectionDataPackageRequest(
                username=username,
                server_host=self._host_for_bundle(request),
                server_port=self._settings.cot_port,
                cert_enroll_port=self._settings.enroll_port,
                use_tls=use_tls,
                mode=mode,
                zip_name=zip_name,
                lets_encrypt=lets_encrypt,
                truststore_p12_base64=(
                    base64.b64encode(truststore).decode("ascii") if truststore else None
                ),
            )
        )
        return package.content

    async def _dispatch(self, request: EnrollRequest, writer: asyncio.StreamWriter) -> None:
        if request.path == "/health" and request.method == "GET":
            await self._write_json(writer, 200, {"status": "ok"})
            return

        if request.path == "/join/package.zip" and request.method == "GET":
            mode = request.query.get("mode", ["itak"])[0].lower().strip()
            if mode not in {"itak", "atak"}:
                mode = "itak"
            use_tls = _to_bool(request.query.get("tls", [None])[0], default=self._settings.tls_enabled)
            lets_encrypt = _to_bool(
                request.query.get("lets_encrypt", [None])[0],
                default=self._settings.enroll_letsencrypt or (use_tls and not bool(self._truststore_bytes())),
            )
            username = request.query.get("username", ["operator"])[0]
            zip_name = request.query.get("name", [f"{username}-join"])[0]
            content = self._build_connection_package(
                request=request,
                username=username,
                mode=mode,
                use_tls=use_tls,
                lets_encrypt=lets_encrypt,
                zip_name=zip_name,
            )
            await self._write_bytes(
                writer,
                200,
                content,
                content_type="application/zip",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{zip_name}.zip"'
                },
            )
            return

        if request.path == "/join/qr.png" and request.method == "GET":
            mode = request.query.get("mode", ["itak"])[0].lower().strip()
            if mode not in {"itak", "atak"}:
                mode = "itak"
            tls_text = request.query.get("tls", ["true" if self._settings.tls_enabled else "false"])[0]
            lets_encrypt_text = request.query.get(
                "lets_encrypt",
                ["true" if self._settings.enroll_letsencrypt else "false"],
            )[0]
            username = request.query.get("username", ["operator"])[0]
            join_url = (
                f"{self._base_url(request)}/join/package.zip"
                f"?mode={mode}&tls={tls_text}&lets_encrypt={lets_encrypt_text}&username={username}"
            )
            png = render_qr_png(join_url)
            await self._write_bytes(writer, 200, png, content_type="image/png")
            return

        if request.path == "/join" and request.method == "GET":
            mode = request.query.get("mode", ["itak"])[0].lower().strip()
            if mode not in {"itak", "atak"}:
                mode = "itak"
            tls_text = request.query.get("tls", ["true" if self._settings.tls_enabled else "false"])[0]
            lets_encrypt_text = request.query.get(
                "lets_encrypt",
                ["true" if self._settings.enroll_letsencrypt else "false"],
            )[0]
            username = request.query.get("username", ["operator"])[0]
            qr_src = (
                f"/join/qr.png?mode={mode}&tls={tls_text}"
                f"&lets_encrypt={lets_encrypt_text}&username={username}"
            )
            package_link = (
                f"/join/package.zip?mode={mode}&tls={tls_text}"
                f"&lets_encrypt={lets_encrypt_text}&username={username}"
            )
            html = f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>TAK Join QR</title>
    <style>
      body {{ font-family: Arial, sans-serif; margin: 24px; }}
      .box {{ max-width: 560px; border: 1px solid #ddd; padding: 16px; border-radius: 8px; }}
      img {{ width: 320px; height: 320px; border: 1px solid #ddd; }}
      code {{ background: #f5f5f5; padding: 2px 6px; }}
    </style>
  </head>
  <body>
    <div class="box">
      <h2>TAK Join QR</h2>
      <p>Scan this QR in TAK Aware / OmniTAK / iTAK to download a join package.</p>
      <p>Mode: <code>{mode}</code>, TLS: <code>{tls_text}</code>, Enroll Port: <code>{self._settings.enroll_port}</code></p>
      <p><img src="{qr_src}" alt="Join QR" /></p>
      <p>Direct package URL: <a href="{package_link}">{package_link}</a></p>
    </div>
  </body>
</html>"""
            await self._write_bytes(writer, 200, html.encode("utf-8"), content_type="text/html; charset=utf-8")
            return

        if request.path in {"/oauth/token", "/Marti/oauth/token"} and request.method in {"POST", "GET"}:
            user = self._auth_user(request)
            if user is None:
                await self._write_json(writer, 401, {"error": "invalid credentials"})
                return
            token = base64.b64encode(f"{user.username}:{user.user_id}".encode("utf-8")).decode("ascii")
            await self._write_json(
                writer,
                200,
                {
                    "access_token": token,
                    "token_type": "bearer",
                    "username": user.username,
                },
            )
            return

        if request.path in {"/api/truststore", "/Marti/api/truststore"} and request.method == "GET":
            truststore = self._truststore_bytes()
            if not truststore:
                await self._write_json(writer, 404, {"error": "truststore not configured"})
                return
            await self._write_bytes(
                writer,
                200,
                truststore,
                content_type="application/x-pkcs12",
                extra_headers={"Content-Disposition": 'attachment; filename="truststore.p12"'},
            )
            return

        if request.path in {
            "/Marti/api/tls/profile/enrollment",
            "/api/connection",
            "/Marti/api/device/profile/connection",
        } and request.method in {"GET", "POST"}:
            user = self._auth_user(request)
            if user is None:
                await self._write_json(writer, 401, {"error": "authentication required"})
                return

            user_agent = request.headers.get("user-agent", "").lower()
            mode = request.query.get("mode", [""])[0].lower().strip()
            if mode not in {"itak", "atak"}:
                mode = "itak" if ("itak" in user_agent or "omnitak" in user_agent) else "atak"

            use_tls = _to_bool(request.query.get("tls", [None])[0], default=self._settings.tls_enabled)
            lets_encrypt = _to_bool(
                request.query.get("lets_encrypt", [None])[0],
                default=self._settings.enroll_letsencrypt or (use_tls and not bool(self._truststore_bytes())),
            )

            package = self._build_connection_package(
                request=request,
                username=user.username,
                mode=mode,
                use_tls=use_tls,
                lets_encrypt=lets_encrypt,
                zip_name=f"{user.username}-connection",
            )
            await self._write_bytes(
                writer,
                200,
                package,
                content_type="application/zip",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{user.username}-connection.zip"'
                },
            )
            return

        await self._write_json(writer, 404, {"error": "not found"})

    async def _write_json(self, writer: asyncio.StreamWriter, status: int, payload: dict) -> None:
        await self._write_bytes(
            writer=writer,
            status=status,
            payload=json.dumps(payload).encode("utf-8"),
            content_type="application/json",
        )

    async def _write_bytes(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        payload: bytes,
        content_type: str,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> None:
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(payload)),
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)
        lines = [f"HTTP/1.1 {status} {_http_reason(status)}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        lines.append("")
        writer.write("\r\n".join(lines).encode("utf-8") + payload)
        await writer.drain()
