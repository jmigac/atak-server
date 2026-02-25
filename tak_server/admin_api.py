from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from tak_server.repository import Repository, RepositoryError, UserIdentity


@dataclass(frozen=True)
class HttpRequest:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes


def _http_reason(status: int) -> str:
    reasons = {
        200: "OK",
        201: "Created",
        204: "No Content",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        413: "Payload Too Large",
        500: "Internal Server Error",
    }
    return reasons.get(status, "OK")


class AdminApi:
    def __init__(
        self,
        repository: Repository,
        metrics_provider: Callable[[], dict[str, Any]],
        clients_provider: Callable[[], list[dict[str, Any]]],
        max_body_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        self._repository = repository
        self._metrics_provider = metrics_provider
        self._clients_provider = clients_provider
        self._max_body_bytes = max_body_bytes

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
            await self._write_json(writer, 500, {"error": "internal server error"})
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

    async def _read_request(self, reader: asyncio.StreamReader) -> Optional[HttpRequest]:
        try:
            raw_headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        except Exception:
            return None

        lines = raw_headers.decode("utf-8", errors="ignore").split("\r\n")
        if not lines or len(lines[0].split(" ")) < 2:
            return None

        request_line = lines[0].split(" ")
        method = request_line[0].upper()
        target = request_line[1]

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", maxsplit=1)
            headers[key.strip().lower()] = value.strip()

        try:
            content_length = int(headers.get("content-length", "0") or "0")
        except ValueError:
            return HttpRequest(
                method=method,
                path="__BAD_REQUEST__",
                query={},
                headers=headers,
                body=b"",
            )
        if content_length < 0 or content_length > self._max_body_bytes:
            return HttpRequest(
                method=method,
                path="__TOO_LARGE__",
                query={},
                headers=headers,
                body=b"",
            )

        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(reader.readexactly(content_length), timeout=20)

        parsed = urlparse(target)
        return HttpRequest(
            method=method,
            path=parsed.path,
            query=parse_qs(parsed.query),
            headers=headers,
            body=body,
        )

    def _authenticated_user(self, request: HttpRequest) -> Optional[UserIdentity]:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("basic "):
            return None
        encoded = auth_header.split(" ", maxsplit=1)[1].strip()
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return None
        if ":" not in decoded:
            return None
        username, password = decoded.split(":", maxsplit=1)
        return self._repository.authenticate_user(username, password)

    async def _dispatch(self, request: HttpRequest, writer: asyncio.StreamWriter) -> None:
        if request.path == "__TOO_LARGE__":
            await self._write_json(writer, 413, {"error": "payload too large"})
            return
        if request.path == "__BAD_REQUEST__":
            await self._write_json(writer, 400, {"error": "bad request"})
            return

        if request.path == "/health" and request.method == "GET":
            await self._write_json(writer, 200, {"status": "ok"})
            return

        user = self._authenticated_user(request)
        if user is None:
            await self._write_json(
                writer,
                401,
                {"error": "authentication required"},
                extra_headers={"WWW-Authenticate": 'Basic realm="tak-admin"'},
            )
            return

        try:
            await self._route_authenticated(request, writer, user)
        except RepositoryError as exc:
            message = str(exc)
            if "not found" in message:
                status = 404
            elif "denied" in message or "required" in message:
                status = 403
            elif "already exists" in message:
                status = 409
            else:
                status = 400
            await self._write_json(writer, status, {"error": message})

    async def _route_authenticated(
        self,
        request: HttpRequest,
        writer: asyncio.StreamWriter,
        user: UserIdentity,
    ) -> None:
        path = request.path
        method = request.method
        segments = [segment for segment in path.split("/") if segment]

        if path == "/whoami" and method == "GET":
            await self._write_json(
                writer,
                200,
                {
                    "user_id": user.user_id,
                    "username": user.username,
                    "is_admin": user.is_admin,
                    "groups": [{"id": gid, "name": gname} for gid, gname in user.groups.items()],
                },
            )
            return

        if path == "/metrics" and method == "GET":
            await self._write_json(writer, 200, self._metrics_provider())
            return

        if path == "/clients" and method == "GET":
            if not user.is_admin:
                raise RepositoryError("admin role required")
            await self._write_json(writer, 200, {"clients": self._clients_provider()})
            return

        if segments and segments[0] == "users":
            await self._handle_users(request, writer, user, segments)
            return

        if segments and segments[0] == "groups":
            await self._handle_groups(request, writer, user, segments)
            return

        if path == "/memberships" and method == "GET":
            if not user.is_admin:
                raise RepositoryError("admin role required")
            await self._write_json(writer, 200, {"memberships": self._repository.list_memberships()})
            return

        if segments and segments[0] == "policies":
            await self._handle_policies(request, writer, user, segments)
            return

        if segments and segments[0] == "missions":
            await self._handle_missions(request, writer, user, segments)
            return

        if segments and segments[0] == "packages":
            await self._handle_packages(request, writer, user, segments)
            return

        await self._write_json(writer, 404, {"error": "not found"})

    def _json_body(self, request: HttpRequest) -> dict[str, Any]:
        if not request.body:
            return {}
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RepositoryError(f"invalid json body: {exc}") from exc
        if not isinstance(payload, dict):
            raise RepositoryError("json body must be an object")
        return payload

    def _require_int(self, payload: dict[str, Any], key: str) -> int:
        value = payload.get(key)
        if value is None:
            raise RepositoryError(f"{key} is required")
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise RepositoryError(f"{key} must be an integer") from exc

    async def _handle_users(
        self,
        request: HttpRequest,
        writer: asyncio.StreamWriter,
        user: UserIdentity,
        segments: list[str],
    ) -> None:
        if not user.is_admin:
            raise RepositoryError("admin role required")

        if len(segments) == 1 and request.method == "GET":
            await self._write_json(writer, 200, {"users": self._repository.list_users()})
            return

        if len(segments) == 1 and request.method == "POST":
            payload = self._json_body(request)
            created = self._repository.create_user(
                username=str(payload.get("username", "")),
                password=str(payload.get("password", "")),
                is_admin=bool(payload.get("is_admin", False)),
                enabled=bool(payload.get("enabled", True)),
            )
            await self._write_json(writer, 201, created)
            return

        if len(segments) == 2 and request.method in {"PATCH", "PUT"}:
            payload = self._json_body(request)
            updated = self._repository.update_user(
                user_id=int(segments[1]),
                password=payload.get("password"),
                is_admin=payload.get("is_admin"),
                enabled=payload.get("enabled"),
            )
            await self._write_json(writer, 200, updated)
            return

        await self._write_json(writer, 405, {"error": "method not allowed"})

    async def _handle_groups(
        self,
        request: HttpRequest,
        writer: asyncio.StreamWriter,
        user: UserIdentity,
        segments: list[str],
    ) -> None:
        if not user.is_admin:
            raise RepositoryError("admin role required")

        if len(segments) == 1 and request.method == "GET":
            await self._write_json(writer, 200, {"groups": self._repository.list_groups()})
            return

        if len(segments) == 1 and request.method == "POST":
            payload = self._json_body(request)
            created = self._repository.ensure_group(
                name=str(payload.get("name", "")),
                description=payload.get("description"),
            )
            await self._write_json(writer, 201, created)
            return

        if len(segments) == 3 and segments[2] == "members" and request.method == "POST":
            payload = self._json_body(request)
            self._repository.add_user_to_group(
                user_id=self._require_int(payload, "user_id"),
                group_id=int(segments[1]),
                role=str(payload.get("role", "member")),
            )
            await self._write_json(writer, 204, None)
            return

        if len(segments) == 4 and segments[2] == "members" and request.method == "DELETE":
            self._repository.remove_user_from_group(
                user_id=int(segments[3]),
                group_id=int(segments[1]),
            )
            await self._write_json(writer, 204, None)
            return

        await self._write_json(writer, 405, {"error": "method not allowed"})

    async def _handle_policies(
        self,
        request: HttpRequest,
        writer: asyncio.StreamWriter,
        user: UserIdentity,
        segments: list[str],
    ) -> None:
        if not user.is_admin:
            raise RepositoryError("admin role required")

        if len(segments) == 1 and request.method == "GET":
            await self._write_json(writer, 200, {"policies": self._repository.list_policies()})
            return

        if len(segments) == 1 and request.method == "POST":
            payload = self._json_body(request)
            group_name = payload.get("group_name")
            group_id = payload.get("group_id")
            if group_name and not group_id:
                group_id = self._repository.get_group_id_by_name(str(group_name))
                if group_id is None:
                    raise RepositoryError("group not found")
            created = self._repository.create_policy(
                name=str(payload.get("name", "")),
                action=str(payload.get("action", "")),
                cot_type_prefix=str(payload.get("cot_type_prefix", "*")),
                group_id=int(group_id) if group_id is not None else None,
                enabled=bool(payload.get("enabled", True)),
            )
            await self._write_json(writer, 201, created)
            return

        if len(segments) == 2 and request.method in {"PATCH", "PUT"}:
            payload = self._json_body(request)
            group_id = payload.get("group_id")
            if group_id == "null":
                resolved_group_id: Optional[int] | str = "null"
            elif group_id is None:
                resolved_group_id = None
            else:
                resolved_group_id = int(group_id)
            updated = self._repository.update_policy(
                int(segments[1]),
                name=payload.get("name"),
                action=payload.get("action"),
                cot_type_prefix=payload.get("cot_type_prefix"),
                group_id=resolved_group_id,
                enabled=payload.get("enabled"),
            )
            await self._write_json(writer, 200, updated)
            return

        if len(segments) == 2 and request.method == "DELETE":
            self._repository.delete_policy(int(segments[1]))
            await self._write_json(writer, 204, None)
            return

        await self._write_json(writer, 405, {"error": "method not allowed"})

    async def _handle_missions(
        self,
        request: HttpRequest,
        writer: asyncio.StreamWriter,
        user: UserIdentity,
        segments: list[str],
    ) -> None:
        if len(segments) == 1 and request.method == "GET":
            await self._write_json(writer, 200, {"missions": self._repository.list_missions(user)})
            return

        if len(segments) == 1 and request.method == "POST":
            payload = self._json_body(request)
            created = self._repository.create_mission(
                identity=user,
                name=str(payload.get("name", "")),
                description=payload.get("description"),
                group_ids=[int(value) for value in payload.get("group_ids", [])],
            )
            await self._write_json(writer, 201, created)
            return

        if len(segments) == 2 and request.method == "GET":
            mission = self._repository.get_mission(int(segments[1]), user)
            await self._write_json(writer, 200, mission)
            return

        if len(segments) == 3 and segments[2] == "members" and request.method == "POST":
            payload = self._json_body(request)
            self._repository.add_user_to_mission(
                identity=user,
                mission_id=int(segments[1]),
                user_id=self._require_int(payload, "user_id"),
                role=str(payload.get("role", "member")),
            )
            await self._write_json(writer, 204, None)
            return

        if len(segments) == 3 and segments[2] == "groups" and request.method == "POST":
            payload = self._json_body(request)
            self._repository.add_group_to_mission(
                identity=user,
                mission_id=int(segments[1]),
                group_id=self._require_int(payload, "group_id"),
                can_write=bool(payload.get("can_write", False)),
            )
            await self._write_json(writer, 204, None)
            return

        if len(segments) == 3 and segments[2] == "packages" and request.method == "POST":
            payload = self._json_body(request)
            self._repository.attach_package_to_mission(
                identity=user,
                mission_id=int(segments[1]),
                package_id=self._require_int(payload, "package_id"),
            )
            await self._write_json(writer, 204, None)
            return

        await self._write_json(writer, 405, {"error": "method not allowed"})

    async def _handle_packages(
        self,
        request: HttpRequest,
        writer: asyncio.StreamWriter,
        user: UserIdentity,
        segments: list[str],
    ) -> None:
        if len(segments) == 1 and request.method == "GET":
            await self._write_json(writer, 200, {"packages": self._repository.list_data_packages(user)})
            return

        if len(segments) == 1 and request.method == "POST":
            payload = self._json_body(request)
            created = self._repository.create_data_package(
                identity=user,
                name=str(payload.get("name", "")),
                description=payload.get("description"),
                file_name=str(payload.get("file_name", "")),
                content_type=str(payload.get("content_type", "application/octet-stream")),
                content_base64=str(payload.get("content_base64", "")),
                group_ids=[int(value) for value in payload.get("group_ids", [])],
                mission_ids=[int(value) for value in payload.get("mission_ids", [])],
            )
            await self._write_json(writer, 201, created)
            return

        if len(segments) == 2 and request.method == "GET":
            package = self._repository.get_data_package(user, int(segments[1]))
            package.pop("storage_path", None)
            await self._write_json(writer, 200, package)
            return

        if len(segments) == 3 and segments[2] == "download" and request.method == "GET":
            package, content = self._repository.read_package_blob(user, int(segments[1]))
            await self._write_bytes(
                writer,
                200,
                content,
                content_type=str(package["content_type"]),
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{package["file_name"]}"'
                },
            )
            return

        await self._write_json(writer, 405, {"error": "method not allowed"})

    async def _write_json(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        payload: Any,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> None:
        if status == 204:
            await self._write_bytes(writer, status, b"", content_type="application/json", extra_headers=extra_headers)
            return
        encoded = json.dumps(payload).encode("utf-8")
        await self._write_bytes(
            writer,
            status,
            encoded,
            content_type="application/json",
            extra_headers=extra_headers,
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
