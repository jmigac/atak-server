from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

from tak_server.admin_api import AdminApi
from tak_server.config import Settings, build_tls_context, load_settings
from tak_server.cot import CoTValidationError, CoTEvent, parse_cot_event
from tak_server.repository import Repository, UserIdentity


LOGGER = logging.getLogger("tak_server")
READ_CHUNK_BYTES = 4096
MAX_BUFFER_BYTES = 1024 * 1024


@dataclass
class Metrics:
    started_at: float = field(default_factory=time.time)
    total_connections: int = 0
    messages_in: int = 0
    messages_out: int = 0
    invalid_messages: int = 0
    auth_failures: int = 0
    queue_drops: int = 0
    idle_timeouts: int = 0
    policy_blocks: int = 0


@dataclass
class ClientSession:
    session_id: str
    peer: str
    connected_at: float
    queue: asyncio.Queue[bytes]
    writer: asyncio.StreamWriter
    authenticated: bool
    identity: Optional[UserIdentity] = None


class ServerState:
    def __init__(self) -> None:
        self.sessions: Dict[str, ClientSession] = {}
        self.metrics = Metrics()

    def register(self, session: ClientSession) -> None:
        self.sessions[session.session_id] = session
        self.metrics.total_connections += 1

    def unregister(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)

    def snapshot(self) -> dict:
        now = time.time()
        return {
            "uptime_seconds": int(now - self.metrics.started_at),
            "connected_clients": len(self.sessions),
            "total_connections": self.metrics.total_connections,
            "messages_in": self.metrics.messages_in,
            "messages_out": self.metrics.messages_out,
            "invalid_messages": self.metrics.invalid_messages,
            "auth_failures": self.metrics.auth_failures,
            "queue_drops": self.metrics.queue_drops,
            "idle_timeouts": self.metrics.idle_timeouts,
            "policy_blocks": self.metrics.policy_blocks,
        }

    def clients_snapshot(self) -> list[dict]:
        now = time.time()
        clients = []
        for session in self.sessions.values():
            groups = []
            if session.identity is not None:
                groups = [{"id": gid, "name": name} for gid, name in session.identity.groups.items()]
            clients.append(
                {
                    "session_id": session.session_id,
                    "peer": session.peer,
                    "connected_seconds": int(now - session.connected_at),
                    "authenticated": session.authenticated,
                    "username": session.identity.username if session.identity else None,
                    "groups": groups,
                    "queued_messages": session.queue.qsize(),
                }
            )
        return clients


def _next_frame(buffer: bytes) -> tuple[bytes, bytes] | tuple[None, bytes]:
    separators = []
    for separator in (b"\n", b"\x00"):
        index = buffer.find(separator)
        if index >= 0:
            separators.append(index)

    if not separators:
        return None, buffer

    split_at = min(separators)
    frame = buffer[:split_at].strip()
    remainder = buffer[split_at + 1 :]
    return frame, remainder


async def _writer_worker(session: ClientSession) -> None:
    try:
        while True:
            payload = await session.queue.get()
            session.writer.write(payload)
            await session.writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        raise


def _queue_for_session(state: ServerState, session: ClientSession, payload: bytes) -> bool:
    try:
        session.queue.put_nowait(payload)
        return True
    except asyncio.QueueFull:
        try:
            session.queue.get_nowait()
        except asyncio.QueueEmpty:
            pass

        try:
            session.queue.put_nowait(payload)
            state.metrics.queue_drops += 1
            return True
        except asyncio.QueueFull:
            state.metrics.queue_drops += 1
            return False


def _can_deliver_to_recipient(
    repository: Repository,
    sender: ClientSession,
    recipient: ClientSession,
    event: CoTEvent,
    target_group_id: Optional[int],
) -> bool:
    if not recipient.authenticated:
        return False
    if recipient.identity is None:
        return True
    if sender.identity is None:
        return True

    sender_groups = sender.identity.group_ids
    recipient_groups = recipient.identity.group_ids

    if target_group_id is not None:
        if target_group_id not in sender_groups:
            return False
        if target_group_id not in recipient_groups:
            return False
    elif sender_groups and recipient_groups and sender_groups.isdisjoint(recipient_groups):
        return False

    return repository.can_perform_action(
        recipient.identity,
        action="subscribe",
        cot_type=event.cot_type,
        scope_group_id=target_group_id,
    )


def _broadcast_event(
    repository: Repository,
    state: ServerState,
    sender: ClientSession,
    event: CoTEvent,
    target_group_id: Optional[int],
) -> int:
    delivered = 0
    wire_payload = event.raw + b"\n"
    for recipient in list(state.sessions.values()):
        if recipient.session_id == sender.session_id:
            continue
        if not _can_deliver_to_recipient(repository, sender, recipient, event, target_group_id):
            continue
        if _queue_for_session(state, recipient, wire_payload):
            delivered += 1
    return delivered


def _parse_auth_frame(frame: bytes) -> tuple[str, str] | None:
    text = frame.decode("utf-8", errors="ignore").strip()
    parts = text.split(" ")
    if len(parts) != 3 or parts[0].upper() != "AUTH":
        return None
    return parts[1], parts[2]


async def _handle_cot_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: Settings,
    state: ServerState,
    repository: Repository,
) -> None:
    peer = writer.get_extra_info("peername")
    peer_str = str(peer) if peer else "unknown"
    session = ClientSession(
        session_id=uuid.uuid4().hex[:12],
        peer=peer_str,
        connected_at=time.time(),
        queue=asyncio.Queue(maxsize=settings.queue_size),
        writer=writer,
        authenticated=not settings.require_client_auth,
    )
    state.register(session)
    writer_task = asyncio.create_task(_writer_worker(session))
    buffer = b""
    LOGGER.info("client connected session=%s peer=%s", session.session_id, session.peer)

    try:
        if settings.require_client_auth:
            _queue_for_session(
                state,
                session,
                b"# Authentication required. Send: AUTH <username> <password>\n",
            )

        while True:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(READ_CHUNK_BYTES),
                    timeout=settings.idle_timeout_seconds,
                )
            except TimeoutError:
                state.metrics.idle_timeouts += 1
                LOGGER.info("client idle timeout session=%s", session.session_id)
                break

            if not chunk:
                break

            buffer += chunk
            if len(buffer) > MAX_BUFFER_BYTES:
                LOGGER.warning(
                    "client buffer limit exceeded session=%s size=%d",
                    session.session_id,
                    len(buffer),
                )
                break

            while True:
                frame, buffer = _next_frame(buffer)
                if frame is None:
                    break
                if not frame:
                    continue

                if settings.require_client_auth and not session.authenticated:
                    auth = _parse_auth_frame(frame)
                    if auth is not None:
                        username, password = auth
                        identity = repository.authenticate_user(username, password)
                        if identity is not None:
                            session.identity = identity
                            session.authenticated = True
                            _queue_for_session(state, session, b"AUTH OK\n")
                            LOGGER.info(
                                "client authenticated session=%s username=%s",
                                session.session_id,
                                identity.username,
                            )
                            continue

                    if settings.auth_token:
                        supplied = frame.decode("utf-8", errors="ignore").strip()
                        if supplied.startswith("AUTH_TOKEN "):
                            token = supplied.split(" ", maxsplit=1)[1]
                            if token == settings.auth_token:
                                identity = repository.authenticate_user(
                                    settings.bootstrap_admin_username,
                                    settings.bootstrap_admin_password,
                                )
                                session.identity = identity
                                session.authenticated = True
                                _queue_for_session(state, session, b"AUTH OK\n")
                                continue

                    state.metrics.auth_failures += 1
                    _queue_for_session(state, session, b"AUTH FAILED\n")
                    LOGGER.info("client authentication failed session=%s", session.session_id)
                    await asyncio.sleep(0.05)
                    return

                try:
                    event = parse_cot_event(frame)
                except CoTValidationError as exc:
                    state.metrics.invalid_messages += 1
                    LOGGER.debug(
                        "invalid CoT session=%s peer=%s error=%s",
                        session.session_id,
                        session.peer,
                        str(exc),
                    )
                    continue

                target_group_id: Optional[int] = None
                if event.target_group:
                    target_group_id = repository.get_group_id_by_name(event.target_group)
                    if target_group_id is None:
                        state.metrics.policy_blocks += 1
                        LOGGER.debug(
                            "message blocked unknown target group session=%s group=%s",
                            session.session_id,
                            event.target_group,
                        )
                        continue

                if session.identity is not None:
                    if target_group_id is not None and target_group_id not in session.identity.group_ids:
                        state.metrics.policy_blocks += 1
                        continue
                    can_publish = repository.can_perform_action(
                        session.identity,
                        action="publish",
                        cot_type=event.cot_type,
                        scope_group_id=target_group_id,
                    )
                    if not can_publish:
                        state.metrics.policy_blocks += 1
                        continue

                state.metrics.messages_in += 1
                delivered = _broadcast_event(
                    repository=repository,
                    state=state,
                    sender=session,
                    event=event,
                    target_group_id=target_group_id,
                )
                state.metrics.messages_out += delivered
    except (ConnectionError, asyncio.IncompleteReadError):
        LOGGER.info("client disconnected session=%s", session.session_id)
    finally:
        writer_task.cancel()
        with contextlib.suppress(BaseException):
            await writer_task
        state.unregister(session.session_id)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        LOGGER.info("session closed session=%s", session.session_id)


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


async def run() -> None:
    _configure_logging()
    settings = load_settings()
    state = ServerState()
    repository = Repository(db_path=settings.db_path, data_dir=settings.data_dir)
    repository.bootstrap(
        admin_username=settings.bootstrap_admin_username,
        admin_password=settings.bootstrap_admin_password,
        default_group=settings.default_group_name,
    )

    admin_api = AdminApi(
        repository=repository,
        metrics_provider=state.snapshot,
        clients_provider=state.clients_snapshot,
    )
    tls_context = build_tls_context(settings)
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    cot_server = await asyncio.start_server(
        lambda r, w: _handle_cot_client(r, w, settings, state, repository),
        host=settings.bind_host,
        port=settings.cot_port,
        ssl=tls_context,
    )
    admin_server = await asyncio.start_server(
        admin_api.handle_client,
        host=settings.bind_host,
        port=settings.admin_port,
    )
    cot_addresses = ", ".join(str(sock.getsockname()) for sock in cot_server.sockets or [])
    admin_addresses = ", ".join(str(sock.getsockname()) for sock in admin_server.sockets or [])

    LOGGER.info("CoT server listening on %s tls=%s", cot_addresses, bool(tls_context))
    LOGGER.info("Admin server listening on %s", admin_addresses)

    try:
        async with cot_server, admin_server:
            await stop_event.wait()
            LOGGER.info("shutdown signal received")
    finally:
        repository.close()
