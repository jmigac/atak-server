# TAK-like CoT Router (Python)

This project provides a TAK-style server MVP with:
- CoT XML TCP ingest + fan-out routing.
- TAK-style binary framing compatibility (varint length-prefixed payloads with embedded CoT extraction).
- User authentication for CoT clients (`AUTH <username> <password>`).
- Certificate authentication (mTLS) with optional auto-provisioned users from client cert identity.
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
- CoT TLS: `8089`
- Admin API HTTP: `8088`
- Enrollment API: `8446`

Bootstrap admin (from `compose.yaml` defaults):
- username: `admin`
- password: `admin12345`

## CoT client authentication

After connecting to TCP `8087` (or TLS `8089`), authenticate before sending CoT:

```text
AUTH admin admin12345
```

Then send CoT XML frames delimited by newline (`\n`) or null (`\0`).

For TAK protocol compatibility, the server also accepts varint length-prefixed frames and will extract embedded `<event>...</event>` CoT XML when present.

## iTAK certificate-auth mode

1. Enable TLS and client certificate validation:

```yaml
TAK_TLS_ENABLED: "true"
TAK_TLS_REQUIRE_CLIENT_CERT: "true"
TAK_TLS_CA_FILE: "/app/certs/ca.crt"
TAK_TLS_CERT_FILE: "/app/certs/server.crt"
TAK_TLS_KEY_FILE: "/app/certs/server.key"
TAK_REQUIRE_CLIENT_AUTH: "true"
TAK_CERT_AUTH_ENABLED: "true"
TAK_CERT_AUTO_PROVISION: "true"
TAK_ALLOW_PASSWORD_AUTH: "false"
```

For Let's Encrypt-managed certs you can use:

```yaml
TAK_TLS_ENABLED: "true"
TAK_TLS_LETSENCRYPT_DOMAIN: "tak.example.com"
TAK_TLS_LETSENCRYPT_DIR: "/etc/letsencrypt/live"
```

and mount `/etc/letsencrypt` read-only into the container.

2. Mount cert files into `/app/certs`.
3. Install the client certificate (issued by your CA) in iTAK.
4. In iTAK server connection, use:
- Protocol: `TCP` (SSL/TLS enabled in the profile)
- Host: your server DNS/IP
- Port: `8089`
- Certificate auth enabled in iTAK profile

TAK Aware and OmniTAK commonly require enrollment endpoint availability on `8446`.
This server now exposes enrollment-compatible paths on that port:
- `GET /Marti/api/tls/profile/enrollment`
- `GET /api/connection`
- `GET /api/truststore`
- `POST/GET /oauth/token`

## Non-secure TCP mode

Yes, you can run without TLS and use plain TCP.

- Set server-side `TAK_TLS_ENABLED=false`.
- In bundle/API payload use `use_tls=false` (or script flag `--tcp`).
- iTAK profile should use TCP with SSL/TLS disabled.

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
- `POST /packages/connection-bundle` (generate TAK/iTAK connection ZIP)
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

Generate iTAK connection bundle ZIP for direct download (TLS):

```bash
CA_B64=$(base64 < certs/truststore-YOUR-CA.p12 | tr -d '\n')
curl -u admin:admin12345 \
  -H "Content-Type: application/json" \
  -d "{\"server_host\":\"tak.example.com\",\"server_port\":8089,\"mode\":\"itak\",\"zip_name\":\"tak-itak-connection\",\"truststore_p12_base64\":\"$CA_B64\"}" \
  http://localhost:8088/packages/connection-bundle \
  -o tak-itak-connection.zip
```

Use plain host/IP for `server_host` (no path). If you pass `https://host/path`, the server normalizes it to host.

Generate iTAK connection bundle for Let's Encrypt/public CA (no truststore upload):

```bash
curl -u admin:admin12345 \
  -H "Content-Type: application/json" \
  -d "{\"server_host\":\"tak.example.com\",\"server_port\":8089,\"cert_enroll_port\":8446,\"mode\":\"itak\",\"zip_name\":\"tak-itak-connection\",\"use_tls\":true,\"lets_encrypt\":true}" \
  http://localhost:8088/packages/connection-bundle \
  -o tak-itak-connection.zip
```

Generate and store bundle as managed server package:

```bash
CA_B64=$(base64 < certs/truststore-YOUR-CA.p12 | tr -d '\n')
curl -u admin:admin12345 \
  -H "Content-Type: application/json" \
  -d "{\"server_host\":\"tak.example.com\",\"server_port\":8089,\"mode\":\"itak\",\"name\":\"itak-server-connection\",\"store\":true,\"truststore_p12_base64\":\"$CA_B64\"}" \
  http://localhost:8088/packages/connection-bundle
```

Local Bash generator (calls API endpoint and writes ZIP):

```bash
scripts/generate_connection_datapackage.sh \
  --server-host tak.example.com \
  --server-port 8089 \
  --enroll-port 8446 \
  --mode itak \
  --tls \
  --ca-cert certs/ca.crt \
  --output ./tak-itak-connection.zip
```

Create truststore automatically from remote TLS server cert:

```bash
scripts/generate_connection_datapackage.sh \
  --server-host tak.example.com \
  --server-port 8089 \
  --enroll-port 8446 \
  --mode itak \
  --tls \
  --fetch-server-cert \
  --output ./tak-itak-connection.zip
```

Non-secure TCP bundle (no truststore needed):

```bash
scripts/generate_connection_datapackage.sh \
  --server-host tak.example.com \
  --server-port 8087 \
  --enroll-port 8446 \
  --mode itak \
  --tcp \
  --output ./tak-itak-connection-tcp.zip
```

Let's Encrypt/public CA bundle (TLS, no truststore generation):

```bash
scripts/generate_connection_datapackage.sh \
  --server-host tak.example.com \
  --server-port 8089 \
  --enroll-port 8446 \
  --mode itak \
  --lets-encrypt \
  --output ./tak-itak-connection-le.zip
```

## Environment variables

- `TAK_BIND_HOST` (default `0.0.0.0`)
- `TAK_COT_PORT` (default `8087`)
- `TAK_COT_SSL_PORT` (default `8089`)
- `TAK_ADMIN_PORT` (default `8088`)
- `TAK_LOG_LEVEL` (default `INFO`; set `DEBUG` for extra diagnostics)
- `TAK_IDLE_TIMEOUT_SECONDS` (default `120`)
- `TAK_QUEUE_SIZE` (default `500`)
- `TAK_DB_PATH` (default `/app/data/tak_server.db`)
- `TAK_DATA_DIR` (default `/app/data`)
- `TAK_DEFAULT_GROUP_NAME` (default `default`)
- `TAK_PUBLIC_HOST` (optional public hostname used by enrollment profiles)
- `TAK_BOOTSTRAP_ADMIN_USERNAME` (default `admin`)
- `TAK_BOOTSTRAP_ADMIN_PASSWORD` (default `admin12345`)
- `TAK_REQUIRE_CLIENT_AUTH` (default `false`)
- `TAK_ALLOW_PASSWORD_AUTH` (default `true`)
- `TAK_CERT_AUTH_ENABLED` (default `false`)
- `TAK_CERT_AUTO_PROVISION` (default `true`)
- `TAK_AUTH_TOKEN` (optional legacy fallback for `AUTH_TOKEN <token>`)
- `TAK_TLS_ENABLED` (default `false`)
- `TAK_TLS_REQUIRE_CLIENT_CERT` (default `false`)
- `TAK_TLS_CA_FILE` (required for certificate validation)
- `TAK_TLS_CA_PATH` (optional trust store path)
- `TAK_TLS_CERT_FILE` (required when TLS enabled)
- `TAK_TLS_KEY_FILE` (required when TLS enabled)
- `TAK_TLS_LETSENCRYPT_DOMAIN` (optional LE domain to auto-load `/etc/letsencrypt/live/<domain>/fullchain.pem` + `privkey.pem`)
- `TAK_TLS_LETSENCRYPT_DIR` (default `/etc/letsencrypt/live`)
- `TAK_ENROLL_ENABLED` (default `true`)
- `TAK_ENROLL_PORT` (default `8446`)
- `TAK_ENROLL_TRUSTSTORE_P12_FILE` (optional path used by `/api/truststore`)
- `TAK_ENROLL_LETSENCRYPT` (default `false`; when true enrollment profiles default to public-CA mode)

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
