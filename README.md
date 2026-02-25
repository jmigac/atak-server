# TAK-like CoT Router (Python)

This project provides a TAK-style server MVP with:
- CoT XML TCP ingest + fan-out routing.
- User authentication for CoT clients (`AUTH <username> <password>`).
- Group-aware and policy-aware publish/subscribe enforcement.
- Mission workflows (create, member/group assignment, package linkage).
- Data package workflows (upload metadata/content, list, download, attach to missions).
- Admin REST API for users, groups, memberships, and policies.
- Dockerized runtime with multi-arch image builds (`linux/amd64`, `linux/arm64`).

## Run locally

```bash
docker compose up --build
```

Ports:
- CoT TCP: `8087`
- Admin API HTTP: `8088`

Bootstrap admin (from `compose.yaml` defaults):
- username: `admin`
- password: `admin12345`

## CoT client authentication

After connecting to TCP `8087`, authenticate before sending CoT:

```text
AUTH admin admin12345
```

Then send CoT XML frames delimited by newline (`\n`) or null (`\0`).

## Admin API authentication

All admin endpoints except `/health` require HTTP Basic auth.

Example:

```bash
curl -u admin:admin12345 http://localhost:8088/whoami
```

## Core admin endpoints

Health/observability:
- `GET /health`
- `GET /metrics`
- `GET /clients`
- `GET /whoami`

Users:
- `GET /users`
- `POST /users`
- `PATCH /users/{id}`

Groups & membership:
- `GET /groups`
- `POST /groups`
- `GET /memberships`
- `POST /groups/{group_id}/members`
- `DELETE /groups/{group_id}/members/{user_id}`

Policies:
- `GET /policies`
- `POST /policies`
- `PATCH /policies/{id}`
- `DELETE /policies/{id}`

Missions:
- `GET /missions`
- `POST /missions`
- `GET /missions/{id}`
- `POST /missions/{id}/members`
- `POST /missions/{id}/groups`
- `POST /missions/{id}/packages`

Data packages:
- `GET /packages`
- `POST /packages`
- `GET /packages/{id}`
- `GET /packages/{id}/download`

## Example API workflow

Create user:

```bash
curl -u admin:admin12345 \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alicepass123","is_admin":false}' \
  http://localhost:8088/users
```

Create group:

```bash
curl -u admin:admin12345 \
  -H "Content-Type: application/json" \
  -d '{"name":"blue-team","description":"Blue operators"}' \
  http://localhost:8088/groups
```

Add user to group:

```bash
curl -u admin:admin12345 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"user_id":2,"role":"member"}' \
  http://localhost:8088/groups/2/members
```

Create policy (blue-team publish CoT type prefix):

```bash
curl -u admin:admin12345 \
  -H "Content-Type: application/json" \
  -d '{"name":"blue-publish","action":"publish","cot_type_prefix":"a-f-","group_id":2}' \
  http://localhost:8088/policies
```

Create mission:

```bash
curl -u admin:admin12345 \
  -H "Content-Type: application/json" \
  -d '{"name":"Mission Alpha","description":"Field operation","group_ids":[2]}' \
  http://localhost:8088/missions
```

Create package (content is base64):

```bash
DATA_B64=$(printf "hello mission package" | base64)
curl -u admin:admin12345 \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"briefing\",\"file_name\":\"brief.txt\",\"content_type\":\"text/plain\",\"content_base64\":\"$DATA_B64\",\"group_ids\":[2],\"mission_ids\":[1]}" \
  http://localhost:8088/packages
```

## Environment variables

- `TAK_BIND_HOST` (default `0.0.0.0`)
- `TAK_COT_PORT` (default `8087`)
- `TAK_ADMIN_PORT` (default `8088`)
- `TAK_IDLE_TIMEOUT_SECONDS` (default `120`)
- `TAK_QUEUE_SIZE` (default `500`)
- `TAK_DB_PATH` (default `/app/data/tak_server.db`)
- `TAK_DATA_DIR` (default `/app/data`)
- `TAK_DEFAULT_GROUP_NAME` (default `default`)
- `TAK_BOOTSTRAP_ADMIN_USERNAME` (default `admin`)
- `TAK_BOOTSTRAP_ADMIN_PASSWORD` (default `admin12345`)
- `TAK_REQUIRE_CLIENT_AUTH` (default `true`)
- `TAK_AUTH_TOKEN` (optional legacy fallback for `AUTH_TOKEN <token>`)
- `TAK_TLS_ENABLED` (default `false`)
- `TAK_TLS_CERT_FILE` (required when TLS enabled)
- `TAK_TLS_KEY_FILE` (required when TLS enabled)

## Build single-arch image

```bash
docker build -t tak-server:latest .
```

## Build multi-arch image (amd64 + arm64)

```bash
docker buildx create --name takbuilder --use
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t your-registry/tak-server:latest \
  --push .
```

## Makefile shortcuts

```bash
make run
make build IMAGE=tak-server TAG=latest
make build-multiarch IMAGE=your-registry/tak-server TAG=latest
```
