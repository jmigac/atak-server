from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


POLICY_ACTIONS = {
    "publish",
    "subscribe",
    "mission_manage",
    "package_read",
    "package_write",
}


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    rounds = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, encoded: str) -> bool:
    parts = encoded.split("$")
    if len(parts) != 4:
        return False
    algorithm, rounds_text, salt_hex, digest_hex = parts
    if algorithm != "pbkdf2_sha256":
        return False
    try:
        rounds = int(rounds_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return secrets.compare_digest(actual, expected)


def _safe_file_name(file_name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {".", "-", "_"} else "_" for ch in file_name)
    return cleaned.strip("._") or "package.bin"


def _sanitize_username(value: str) -> str:
    allowed = []
    for ch in value.strip().lower():
        if ch.isalnum() or ch in {"-", "_", "."}:
            allowed.append(ch)
        else:
            allowed.append("-")
    text = "".join(allowed).strip("-_.")
    if not text:
        return "cert-user"
    return text[:60]


@dataclass(frozen=True)
class PolicyRule:
    action: str
    cot_type_prefix: str
    group_id: Optional[int]


@dataclass(frozen=True)
class UserIdentity:
    user_id: int
    username: str
    is_admin: bool
    enabled: bool
    groups: dict[int, str]
    policies: tuple[PolicyRule, ...]

    @property
    def group_ids(self) -> set[int]:
        return set(self.groups.keys())


class RepositoryError(ValueError):
    pass


class Repository:
    def __init__(self, db_path: str, data_dir: str) -> None:
        self._db_path = db_path
        db_parent = Path(db_path).expanduser().resolve().parent
        db_parent.mkdir(parents=True, exist_ok=True)

        root_dir = Path(data_dir).expanduser().resolve()
        root_dir.mkdir(parents=True, exist_ok=True)
        self._package_dir = root_dir / "packages"
        self._package_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tak_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_group_memberships (
                    user_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    PRIMARY KEY (user_id, group_id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (group_id) REFERENCES tak_groups(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS user_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL UNIQUE,
                    subject_cn TEXT,
                    subject_dn TEXT,
                    serial_number TEXT,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    action TEXT NOT NULL,
                    cot_type_prefix TEXT NOT NULL DEFAULT '*',
                    group_id INTEGER,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (group_id) REFERENCES tak_groups(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS missions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    created_by INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS mission_members (
                    mission_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    PRIMARY KEY (mission_id, user_id),
                    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS mission_groups (
                    mission_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL,
                    can_write INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (mission_id, group_id),
                    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
                    FOREIGN KEY (group_id) REFERENCES tak_groups(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS data_packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    file_name TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    created_by INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS package_groups (
                    package_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL,
                    can_write INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (package_id, group_id),
                    FOREIGN KEY (package_id) REFERENCES data_packages(id) ON DELETE CASCADE,
                    FOREIGN KEY (group_id) REFERENCES tak_groups(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS mission_packages (
                    mission_id INTEGER NOT NULL,
                    package_id INTEGER NOT NULL,
                    PRIMARY KEY (mission_id, package_id),
                    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
                    FOREIGN KEY (package_id) REFERENCES data_packages(id) ON DELETE CASCADE
                );
                """
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def bootstrap(self, admin_username: str, admin_password: str, default_group: str) -> None:
        if not admin_username or not admin_password:
            raise RepositoryError("admin bootstrap credentials must be provided")

        default_group_id = self.ensure_group(default_group, "Default TAK operators group")["id"]
        admin = self.get_user_by_username(admin_username)
        if admin is None:
            admin = self.create_user(
                username=admin_username,
                password=admin_password,
                is_admin=True,
                enabled=True,
                add_default_group=False,
            )

        self.add_user_to_group(admin["id"], default_group_id, "admin")
        self.ensure_default_policies(default_group_id)

    def ensure_default_policies(self, group_id: int) -> None:
        defaults = (
            ("default-group-publish", "publish", "*"),
            ("default-group-subscribe", "subscribe", "*"),
            ("default-group-mission-manage", "mission_manage", "*"),
            ("default-group-package-read", "package_read", "*"),
            ("default-group-package-write", "package_write", "*"),
        )
        with self._lock:
            for name, action, prefix in defaults:
                row = self._conn.execute(
                    "SELECT id FROM policies WHERE name=?",
                    (name,),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        """
                        INSERT INTO policies(name, action, cot_type_prefix, group_id, enabled, created_at)
                        VALUES (?, ?, ?, ?, 1, ?)
                        """,
                        (name, action, prefix, group_id, _utc_timestamp()),
                    )
            self._conn.commit()

    def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, username, is_admin, enabled, created_at FROM users WHERE username=?",
                (username,),
            ).fetchone()
            if row is None:
                return None
            return dict(row)

    def get_user_by_id(self, user_id: int) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, username, is_admin, enabled, created_at FROM users WHERE id=?",
                (user_id,),
            ).fetchone()
            return dict(row) if row else None

    def _group_ids_for_user_locked(self, user_id: int) -> dict[int, str]:
        rows = self._conn.execute(
            """
            SELECT g.id, g.name
            FROM tak_groups g
            INNER JOIN user_group_memberships ug ON ug.group_id = g.id
            WHERE ug.user_id = ?
            """,
            (user_id,),
        ).fetchall()
        return {int(row["id"]): str(row["name"]) for row in rows}

    def _policy_rules_for_groups_locked(self, group_ids: set[int]) -> tuple[PolicyRule, ...]:
        if group_ids:
            placeholders = ",".join("?" for _ in group_ids)
            rows = self._conn.execute(
                f"""
                SELECT action, cot_type_prefix, group_id
                FROM policies
                WHERE enabled=1 AND (group_id IS NULL OR group_id IN ({placeholders}))
                """,
                tuple(group_ids),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT action, cot_type_prefix, group_id
                FROM policies
                WHERE enabled=1 AND group_id IS NULL
                """
            ).fetchall()

        return tuple(
            PolicyRule(
                action=str(row["action"]),
                cot_type_prefix=str(row["cot_type_prefix"]),
                group_id=int(row["group_id"]) if row["group_id"] is not None else None,
            )
            for row in rows
        )

    def _identity_for_user_id_locked(self, user_id: int) -> Optional[UserIdentity]:
        user = self._conn.execute(
            """
            SELECT id, username, is_admin, enabled
            FROM users
            WHERE id=?
            """,
            (user_id,),
        ).fetchone()
        if user is None or int(user["enabled"]) != 1:
            return None

        group_map = self._group_ids_for_user_locked(int(user["id"]))
        policy_rules = self._policy_rules_for_groups_locked(set(group_map.keys()))
        return UserIdentity(
            user_id=int(user["id"]),
            username=str(user["username"]),
            is_admin=bool(user["is_admin"]),
            enabled=bool(user["enabled"]),
            groups=group_map,
            policies=policy_rules,
        )

    def _next_available_username_locked(self, base_username: str) -> str:
        candidate = _sanitize_username(base_username)
        index = 1
        while True:
            row = self._conn.execute(
                "SELECT 1 FROM users WHERE username=?",
                (candidate,),
            ).fetchone()
            if row is None:
                return candidate
            index += 1
            suffix = f"-{index}"
            max_base = max(1, 60 - len(suffix))
            candidate = f"{_sanitize_username(base_username)[:max_base]}{suffix}"

    def authenticate_user(self, username: str, password: str) -> Optional[UserIdentity]:
        with self._lock:
            user = self._conn.execute(
                """
                SELECT id, username, password_hash, is_admin, enabled
                FROM users
                WHERE username=?
                """,
                (username,),
            ).fetchone()
            if user is None:
                return None
            if int(user["enabled"]) != 1:
                return None
            if not _verify_password(password, str(user["password_hash"])):
                return None
            return self._identity_for_user_id_locked(int(user["id"]))

    def authenticate_certificate(
        self,
        *,
        fingerprint_sha256: str,
        subject_cn: str | None,
        subject_dn: str | None,
        serial_number: str | None,
        auto_provision: bool,
        default_group_name: str = "default",
    ) -> Optional[UserIdentity]:
        with self._lock:
            cert_row = self._conn.execute(
                """
                SELECT uc.user_id, u.enabled
                FROM user_certificates uc
                JOIN users u ON u.id = uc.user_id
                WHERE uc.fingerprint_sha256=?
                """,
                (fingerprint_sha256,),
            ).fetchone()
            if cert_row is not None:
                if int(cert_row["enabled"]) != 1:
                    return None
                self._conn.execute(
                    "UPDATE user_certificates SET last_seen_at=? WHERE fingerprint_sha256=?",
                    (_utc_timestamp(), fingerprint_sha256),
                )
                self._conn.commit()
                return self._identity_for_user_id_locked(int(cert_row["user_id"]))

            if not auto_provision:
                return None

            base = subject_cn or f"cert-{fingerprint_sha256[:12]}"
            username = self._next_available_username_locked(base)
            password_hash = _hash_password(secrets.token_urlsafe(24))
            now = _utc_timestamp()
            cursor = self._conn.execute(
                """
                INSERT INTO users(username, password_hash, is_admin, enabled, created_at)
                VALUES (?, ?, 0, 1, ?)
                """,
                (username, password_hash, now),
            )
            user_id = int(cursor.lastrowid)
            group = self.ensure_group(default_group_name, "Default TAK operators group")
            self._conn.execute(
                """
                INSERT OR IGNORE INTO user_group_memberships(user_id, group_id, role)
                VALUES (?, ?, 'member')
                """,
                (user_id, int(group["id"])),
            )
            self._conn.execute(
                """
                INSERT INTO user_certificates(
                    user_id, fingerprint_sha256, subject_cn, subject_dn, serial_number, created_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    fingerprint_sha256,
                    subject_cn,
                    subject_dn,
                    serial_number,
                    now,
                    now,
                ),
            )
            self._conn.commit()
            return self._identity_for_user_id_locked(user_id)

    def can_perform_action(
        self,
        identity: UserIdentity,
        action: str,
        cot_type: str = "*",
        scope_group_id: Optional[int] = None,
    ) -> bool:
        if identity.is_admin:
            return True
        for rule in identity.policies:
            if rule.action != action:
                continue
            if rule.group_id is not None:
                if scope_group_id is not None and rule.group_id != scope_group_id:
                    continue
                if rule.group_id not in identity.group_ids:
                    continue
            if rule.cot_type_prefix == "*" or cot_type.startswith(rule.cot_type_prefix):
                return True
        return False

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, username, is_admin, enabled, created_at FROM users ORDER BY id"
            ).fetchall()
            return [dict(row) for row in rows]

    def create_user(
        self,
        username: str,
        password: str,
        is_admin: bool = False,
        enabled: bool = True,
        add_default_group: bool = True,
        default_group_name: str = "default",
    ) -> dict[str, Any]:
        username = username.strip()
        if not username:
            raise RepositoryError("username is required")
        if len(password) < 8:
            raise RepositoryError("password must be at least 8 characters")

        with self._lock:
            password_hash = _hash_password(password)
            try:
                cursor = self._conn.execute(
                    """
                    INSERT INTO users(username, password_hash, is_admin, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (username, password_hash, int(is_admin), int(enabled), _utc_timestamp()),
                )
            except sqlite3.IntegrityError as exc:
                raise RepositoryError("username already exists") from exc
            user_id = int(cursor.lastrowid)

            if add_default_group:
                group = self.ensure_group(default_group_name, "Default TAK operators group")
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO user_group_memberships(user_id, group_id, role)
                    VALUES (?, ?, 'member')
                    """,
                    (user_id, int(group["id"])),
                )
            self._conn.commit()

        created = self.get_user_by_id(user_id)
        if created is None:
            raise RepositoryError("failed to read created user")
        return created

    def update_user(
        self,
        user_id: int,
        password: Optional[str] = None,
        is_admin: Optional[bool] = None,
        enabled: Optional[bool] = None,
    ) -> dict[str, Any]:
        updates: list[str] = []
        values: list[Any] = []
        if password is not None:
            if len(password) < 8:
                raise RepositoryError("password must be at least 8 characters")
            updates.append("password_hash=?")
            values.append(_hash_password(password))
        if is_admin is not None:
            updates.append("is_admin=?")
            values.append(int(is_admin))
        if enabled is not None:
            updates.append("enabled=?")
            values.append(int(enabled))
        if not updates:
            raise RepositoryError("no fields to update")

        with self._lock:
            values.append(user_id)
            self._conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", tuple(values))
            self._conn.commit()

        updated = self.get_user_by_id(user_id)
        if updated is None:
            raise RepositoryError("user not found")
        return updated

    def ensure_group(self, name: str, description: str | None = None) -> dict[str, Any]:
        cleaned = name.strip()
        if not cleaned:
            raise RepositoryError("group name is required")

        with self._lock:
            existing = self._conn.execute(
                "SELECT id, name, description, created_at FROM tak_groups WHERE name=?",
                (cleaned,),
            ).fetchone()
            if existing is not None:
                return dict(existing)

            cursor = self._conn.execute(
                "INSERT INTO tak_groups(name, description, created_at) VALUES (?, ?, ?)",
                (cleaned, description, _utc_timestamp()),
            )
            self._conn.commit()

            group = self._conn.execute(
                "SELECT id, name, description, created_at FROM tak_groups WHERE id=?",
                (cursor.lastrowid,),
            ).fetchone()
            if group is None:
                raise RepositoryError("failed to create group")
            return dict(group)

    def list_groups(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT g.id, g.name, g.description, g.created_at, COUNT(ug.user_id) AS member_count
                FROM tak_groups g
                LEFT JOIN user_group_memberships ug ON ug.group_id=g.id
                GROUP BY g.id
                ORDER BY g.id
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def add_user_to_group(self, user_id: int, group_id: int, role: str = "member") -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO user_group_memberships(user_id, group_id, role)
                VALUES (?, ?, ?)
                """,
                (user_id, group_id, role),
            )
            self._conn.commit()

    def remove_user_from_group(self, user_id: int, group_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM user_group_memberships WHERE user_id=? AND group_id=?",
                (user_id, group_id),
            )
            self._conn.commit()

    def list_memberships(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT u.id AS user_id, u.username, g.id AS group_id, g.name AS group_name, ug.role
                FROM user_group_memberships ug
                JOIN users u ON u.id = ug.user_id
                JOIN tak_groups g ON g.id = ug.group_id
                ORDER BY u.username, g.name
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def get_group_id_by_name(self, name: str) -> Optional[int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM tak_groups WHERE name=?",
                (name,),
            ).fetchone()
            return int(row["id"]) if row else None

    def create_policy(
        self,
        name: str,
        action: str,
        cot_type_prefix: str = "*",
        group_id: Optional[int] = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        if action not in POLICY_ACTIONS:
            raise RepositoryError(f"invalid policy action: {action}")
        cot_type_prefix = cot_type_prefix or "*"
        with self._lock:
            try:
                cursor = self._conn.execute(
                    """
                    INSERT INTO policies(name, action, cot_type_prefix, group_id, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (name, action, cot_type_prefix, group_id, int(enabled), _utc_timestamp()),
                )
            except sqlite3.IntegrityError as exc:
                raise RepositoryError("policy name already exists") from exc
            self._conn.commit()

            row = self._conn.execute(
                """
                SELECT p.id, p.name, p.action, p.cot_type_prefix, p.group_id, g.name AS group_name, p.enabled
                FROM policies p
                LEFT JOIN tak_groups g ON g.id = p.group_id
                WHERE p.id=?
                """,
                (cursor.lastrowid,),
            ).fetchone()
            if row is None:
                raise RepositoryError("failed to create policy")
            return dict(row)

    def list_policies(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT p.id, p.name, p.action, p.cot_type_prefix, p.group_id, g.name AS group_name, p.enabled, p.created_at
                FROM policies p
                LEFT JOIN tak_groups g ON g.id = p.group_id
                ORDER BY p.id
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def update_policy(
        self,
        policy_id: int,
        *,
        name: Optional[str] = None,
        action: Optional[str] = None,
        cot_type_prefix: Optional[str] = None,
        group_id: Optional[int] | str = None,
        enabled: Optional[bool] = None,
    ) -> dict[str, Any]:
        updates: list[str] = []
        values: list[Any] = []

        if name is not None:
            updates.append("name=?")
            values.append(name)
        if action is not None:
            if action not in POLICY_ACTIONS:
                raise RepositoryError(f"invalid policy action: {action}")
            updates.append("action=?")
            values.append(action)
        if cot_type_prefix is not None:
            updates.append("cot_type_prefix=?")
            values.append(cot_type_prefix or "*")
        if group_id is not None:
            updates.append("group_id=?")
            values.append(None if group_id == "null" else group_id)
        if enabled is not None:
            updates.append("enabled=?")
            values.append(int(enabled))
        if not updates:
            raise RepositoryError("no fields to update")

        with self._lock:
            values.append(policy_id)
            self._conn.execute(
                f"UPDATE policies SET {', '.join(updates)} WHERE id=?",
                tuple(values),
            )
            self._conn.commit()

            row = self._conn.execute(
                """
                SELECT p.id, p.name, p.action, p.cot_type_prefix, p.group_id, g.name AS group_name, p.enabled
                FROM policies p
                LEFT JOIN tak_groups g ON g.id = p.group_id
                WHERE p.id=?
                """,
                (policy_id,),
            ).fetchone()
            if row is None:
                raise RepositoryError("policy not found")
            return dict(row)

    def delete_policy(self, policy_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM policies WHERE id=?", (policy_id,))
            self._conn.commit()

    def _can_manage_missions(self, identity: UserIdentity) -> bool:
        return self.can_perform_action(identity, "mission_manage")

    def create_mission(
        self,
        identity: UserIdentity,
        name: str,
        description: str | None = None,
        group_ids: Optional[list[int]] = None,
    ) -> dict[str, Any]:
        if not self._can_manage_missions(identity):
            raise RepositoryError("mission_manage policy required")
        if not name.strip():
            raise RepositoryError("mission name is required")

        group_ids = group_ids or []

        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO missions(name, description, created_by, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (name.strip(), description, identity.user_id, _utc_timestamp()),
            )
            mission_id = int(cursor.lastrowid)
            self._conn.execute(
                """
                INSERT INTO mission_members(mission_id, user_id, role)
                VALUES (?, ?, 'owner')
                """,
                (mission_id, identity.user_id),
            )
            for group_id in group_ids:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO mission_groups(mission_id, group_id, can_write)
                    VALUES (?, ?, 1)
                    """,
                    (mission_id, group_id),
                )
            self._conn.commit()

        return self.get_mission(mission_id, identity)

    def _user_has_mission_access_locked(self, identity: UserIdentity, mission_id: int) -> bool:
        if identity.is_admin:
            return True
        member = self._conn.execute(
            "SELECT 1 FROM mission_members WHERE mission_id=? AND user_id=?",
            (mission_id, identity.user_id),
        ).fetchone()
        if member is not None:
            return True
        if not identity.group_ids:
            return False

        placeholders = ",".join("?" for _ in identity.group_ids)
        row = self._conn.execute(
            f"""
            SELECT 1
            FROM mission_groups
            WHERE mission_id=? AND group_id IN ({placeholders})
            LIMIT 1
            """,
            (mission_id, *tuple(identity.group_ids)),
        ).fetchone()
        return row is not None

    def list_missions(self, identity: UserIdentity) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT m.id, m.name, m.description, m.created_by, u.username AS created_by_username, m.created_at
                FROM missions m
                JOIN users u ON u.id = m.created_by
                ORDER BY m.id
                """
            ).fetchall()

            missions = []
            for row in rows:
                mission = dict(row)
                if self._user_has_mission_access_locked(identity, int(mission["id"])):
                    missions.append(mission)
            return missions

    def get_mission(self, mission_id: int, identity: UserIdentity) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT m.id, m.name, m.description, m.created_by, u.username AS created_by_username, m.created_at
                FROM missions m
                JOIN users u ON u.id = m.created_by
                WHERE m.id=?
                """,
                (mission_id,),
            ).fetchone()
            if row is None:
                raise RepositoryError("mission not found")
            if not self._user_has_mission_access_locked(identity, mission_id):
                raise RepositoryError("mission access denied")
            mission = dict(row)

            member_rows = self._conn.execute(
                """
                SELECT mm.user_id, u.username, mm.role
                FROM mission_members mm
                JOIN users u ON u.id = mm.user_id
                WHERE mm.mission_id=?
                ORDER BY u.username
                """,
                (mission_id,),
            ).fetchall()
            group_rows = self._conn.execute(
                """
                SELECT mg.group_id, g.name AS group_name, mg.can_write
                FROM mission_groups mg
                JOIN tak_groups g ON g.id = mg.group_id
                WHERE mg.mission_id=?
                ORDER BY g.name
                """,
                (mission_id,),
            ).fetchall()
            package_rows = self._conn.execute(
                """
                SELECT p.id, p.name, p.file_name, p.size_bytes, p.created_at
                FROM mission_packages mp
                JOIN data_packages p ON p.id = mp.package_id
                WHERE mp.mission_id=?
                ORDER BY p.id
                """,
                (mission_id,),
            ).fetchall()
            mission["members"] = [dict(item) for item in member_rows]
            mission["groups"] = [dict(item) for item in group_rows]
            mission["packages"] = [dict(item) for item in package_rows]
            return mission

    def add_user_to_mission(
        self,
        identity: UserIdentity,
        mission_id: int,
        user_id: int,
        role: str = "member",
    ) -> None:
        if not self._can_manage_missions(identity):
            raise RepositoryError("mission_manage policy required")
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO mission_members(mission_id, user_id, role)
                VALUES (?, ?, ?)
                """,
                (mission_id, user_id, role),
            )
            self._conn.commit()

    def add_group_to_mission(
        self,
        identity: UserIdentity,
        mission_id: int,
        group_id: int,
        can_write: bool = False,
    ) -> None:
        if not self._can_manage_missions(identity):
            raise RepositoryError("mission_manage policy required")
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO mission_groups(mission_id, group_id, can_write)
                VALUES (?, ?, ?)
                """,
                (mission_id, group_id, int(can_write)),
            )
            self._conn.commit()

    def create_data_package(
        self,
        identity: UserIdentity,
        name: str,
        file_name: str,
        content_type: str,
        content_base64: str,
        description: str | None = None,
        group_ids: Optional[list[int]] = None,
        mission_ids: Optional[list[int]] = None,
    ) -> dict[str, Any]:
        if not self.can_perform_action(identity, "package_write"):
            raise RepositoryError("package_write policy required")
        if not name.strip():
            raise RepositoryError("package name is required")
        if not file_name.strip():
            raise RepositoryError("file_name is required")
        if not content_base64:
            raise RepositoryError("content_base64 is required")

        try:
            content = base64.b64decode(content_base64, validate=True)
        except ValueError as exc:
            raise RepositoryError("content_base64 is invalid") from exc

        if len(content) == 0:
            raise RepositoryError("package content is empty")

        safe_name = _safe_file_name(file_name)
        stored_name = f"{uuid.uuid4().hex}_{safe_name}"
        storage_path = self._package_dir / stored_name
        storage_path.write_bytes(content)

        group_ids = group_ids or sorted(identity.group_ids)
        mission_ids = mission_ids or []
        digest = hashlib.sha256(content).hexdigest()

        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO data_packages(
                    name, description, file_name, content_type, size_bytes, sha256, storage_path, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name.strip(),
                    description,
                    safe_name,
                    content_type or "application/octet-stream",
                    len(content),
                    digest,
                    str(storage_path),
                    identity.user_id,
                    _utc_timestamp(),
                ),
            )
            package_id = int(cursor.lastrowid)
            for group_id in group_ids:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO package_groups(package_id, group_id, can_write)
                    VALUES (?, ?, 1)
                    """,
                    (package_id, group_id),
                )
            for mission_id in mission_ids:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO mission_packages(mission_id, package_id)
                    VALUES (?, ?)
                    """,
                    (mission_id, package_id),
                )
            self._conn.commit()

        return self.get_data_package(identity, package_id)

    def _user_has_package_access_locked(self, identity: UserIdentity, package_id: int) -> bool:
        if identity.is_admin:
            return True
        if self.can_perform_action(identity, "package_read"):
            pass
        else:
            return False

        if identity.group_ids:
            placeholders = ",".join("?" for _ in identity.group_ids)
            group_match = self._conn.execute(
                f"""
                SELECT 1
                FROM package_groups
                WHERE package_id=? AND group_id IN ({placeholders})
                LIMIT 1
                """,
                (package_id, *tuple(identity.group_ids)),
            ).fetchone()
            if group_match is not None:
                return True

        mission_rows = self._conn.execute(
            "SELECT mission_id FROM mission_packages WHERE package_id=?",
            (package_id,),
        ).fetchall()
        for mission in mission_rows:
            if self._user_has_mission_access_locked(identity, int(mission["mission_id"])):
                return True
        return False

    def list_data_packages(self, identity: UserIdentity) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT p.id, p.name, p.description, p.file_name, p.content_type, p.size_bytes, p.sha256, p.created_by, u.username AS created_by_username, p.created_at
                FROM data_packages p
                JOIN users u ON u.id = p.created_by
                ORDER BY p.id
                """
            ).fetchall()
            packages = []
            for row in rows:
                package = dict(row)
                if self._user_has_package_access_locked(identity, int(package["id"])):
                    packages.append(package)
            return packages

    def get_data_package(self, identity: UserIdentity, package_id: int) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT p.id, p.name, p.description, p.file_name, p.content_type, p.size_bytes, p.sha256, p.storage_path, p.created_by, u.username AS created_by_username, p.created_at
                FROM data_packages p
                JOIN users u ON u.id = p.created_by
                WHERE p.id=?
                """,
                (package_id,),
            ).fetchone()
            if row is None:
                raise RepositoryError("package not found")
            if not self._user_has_package_access_locked(identity, package_id):
                raise RepositoryError("package access denied")
            package = dict(row)
            groups = self._conn.execute(
                """
                SELECT pg.group_id, g.name AS group_name, pg.can_write
                FROM package_groups pg
                JOIN tak_groups g ON g.id = pg.group_id
                WHERE pg.package_id=?
                ORDER BY g.name
                """,
                (package_id,),
            ).fetchall()
            missions = self._conn.execute(
                """
                SELECT mp.mission_id, m.name AS mission_name
                FROM mission_packages mp
                JOIN missions m ON m.id = mp.mission_id
                WHERE mp.package_id=?
                ORDER BY m.name
                """,
                (package_id,),
            ).fetchall()
            package["groups"] = [dict(item) for item in groups]
            package["missions"] = [dict(item) for item in missions]
            return package

    def read_package_blob(self, identity: UserIdentity, package_id: int) -> tuple[dict[str, Any], bytes]:
        package = self.get_data_package(identity, package_id)
        path = Path(str(package["storage_path"]))
        if not path.exists():
            raise RepositoryError("package file missing on disk")
        content = path.read_bytes()
        return package, content

    def attach_package_to_mission(
        self,
        identity: UserIdentity,
        mission_id: int,
        package_id: int,
    ) -> None:
        if not self._can_manage_missions(identity):
            raise RepositoryError("mission_manage policy required")
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO mission_packages(mission_id, package_id)
                VALUES (?, ?)
                """,
                (mission_id, package_id),
            )
            self._conn.commit()
