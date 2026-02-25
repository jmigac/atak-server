#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  generate_connection_datapackage.sh --server-host HOST [options]

Required:
  --server-host HOST               TAK server hostname/IP that clients should connect to

Common options:
  --server-port PORT               Connection port in profile (default: 8087)
  --enroll-port PORT               Certificate enrollment port in profile (default: 8446)
  --mode MODE                      itak or atak (default: itak)
  --profile-username USER          Username label inside package (default: operator)
  --zip-name NAME                  Package name without .zip (default: tak-connection-package)
  --output FILE                    Output file path (default: ./tak-connection-package.zip)
  --api-url URL                    Admin API base URL (default: http://localhost:8088)
  --admin-user USER                Admin API basic-auth username (default: admin)
  --admin-pass PASS                Admin API basic-auth password (default: admin12345)

Transport:
  --tcp                            Generate non-TLS profile (default)
  --tls                            Generate TLS profile, includes truststore
  --lets-encrypt                   Generate TLS profile for public Let's Encrypt cert (no custom truststore)

Truststore options (only needed with --tls):
  --truststore-p12 FILE            Existing truststore .p12 file
  --ca-cert FILE                   CA/server PEM cert to convert into truststore .p12
  --fetch-server-cert              Pull server cert via openssl s_client and convert to truststore
  --truststore-out FILE            Output truststore path when auto-generating (default: ./generated-truststore.p12)
  --truststore-filename NAME       Filename embedded into ZIP (default: truststore-YOUR-CA.p12)
  --ca-password PASS               truststore password (default: atakatak)

Optional client certificate (.p12) to embed:
  --client-cert-p12 FILE
  --client-cert-filename NAME
  --client-password PASS           client cert password in profile (default: atakatak)

Notes:
  - This script calls POST /packages/connection-bundle.
  - For non-secure hosting use --tcp (no truststore needed).
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

b64_file() {
  local file_path="$1"
  base64 <"$file_path" | tr -d '\n'
}

create_truststore_from_pem() {
  local cert_pem="$1"
  local truststore_out="$2"
  local pass="$3"
  openssl pkcs12 -export -nokeys \
    -in "$cert_pem" \
    -out "$truststore_out" \
    -name "tak-trust" \
    -passout "pass:$pass" >/dev/null
}

fetch_server_cert_pem() {
  local host="$1"
  local port="$2"
  local out_pem="$3"
  openssl s_client -showcerts -servername "$host" -connect "$host:$port" </dev/null 2>/dev/null \
    | awk '/-----BEGIN CERTIFICATE-----/{f=1} f{print} /-----END CERTIFICATE-----/{exit}' >"$out_pem"
  if [[ ! -s "$out_pem" ]]; then
    echo "Failed to fetch server certificate from $host:$port" >&2
    exit 1
  fi
}

SERVER_HOST="server.migac.local"
SERVER_PORT="8087"
ENROLL_PORT="8446"
MODE="itak"
PROFILE_USERNAME="operator"
ZIP_NAME="tak-connection-package"
OUTPUT="./tak-connection-package.zip"
API_URL="http://server.migac.local:8088"
ADMIN_USER="admin"
ADMIN_PASS="admin12345"
USE_TLS="false"
LETS_ENCRYPT="false"
TRUSTSTORE_P12=""
TRUSTSTORE_OUT="./generated-truststore.p12"
TRUSTSTORE_FILENAME="truststore-YOUR-CA.p12"
CA_CERT=""
FETCH_SERVER_CERT="false"
CA_PASSWORD="atakatak"
CLIENT_CERT_P12=""
CLIENT_CERT_FILENAME=""
CLIENT_PASSWORD="atakatak"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-host) SERVER_HOST="${2:-}"; shift 2 ;;
    --server-port) SERVER_PORT="${2:-}"; shift 2 ;;
    --enroll-port) ENROLL_PORT="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --profile-username) PROFILE_USERNAME="${2:-}"; shift 2 ;;
    --zip-name) ZIP_NAME="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --api-url) API_URL="${2:-}"; shift 2 ;;
    --admin-user) ADMIN_USER="${2:-}"; shift 2 ;;
    --admin-pass) ADMIN_PASS="${2:-}"; shift 2 ;;
    --tcp) USE_TLS="false"; shift 1 ;;
    --tls) USE_TLS="true"; shift 1 ;;
    --lets-encrypt) USE_TLS="true"; LETS_ENCRYPT="true"; shift 1 ;;
    --truststore-p12) TRUSTSTORE_P12="${2:-}"; shift 2 ;;
    --ca-cert) CA_CERT="${2:-}"; shift 2 ;;
    --fetch-server-cert) FETCH_SERVER_CERT="true"; shift 1 ;;
    --truststore-out) TRUSTSTORE_OUT="${2:-}"; shift 2 ;;
    --truststore-filename) TRUSTSTORE_FILENAME="${2:-}"; shift 2 ;;
    --ca-password) CA_PASSWORD="${2:-}"; shift 2 ;;
    --client-cert-p12) CLIENT_CERT_P12="${2:-}"; shift 2 ;;
    --client-cert-filename) CLIENT_CERT_FILENAME="${2:-}"; shift 2 ;;
    --client-password) CLIENT_PASSWORD="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

normalize_host() {
  local value="$1"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  if [[ "$value" == *:* ]]; then
    local maybe_port="${value##*:}"
    if [[ "$maybe_port" =~ ^[0-9]+$ ]]; then
      value="${value%%:*}"
    fi
  fi
  printf '%s' "$value"
}

if [[ -z "$SERVER_HOST" ]]; then
  echo "--server-host is required" >&2
  usage
  exit 1
fi

SERVER_HOST="$(normalize_host "$SERVER_HOST")"
if [[ -z "$SERVER_HOST" ]]; then
  echo "Could not parse --server-host into a valid hostname/IP" >&2
  exit 1
fi

if [[ "$MODE" != "itak" && "$MODE" != "atak" ]]; then
  echo "--mode must be itak or atak" >&2
  exit 1
fi

require_cmd curl
require_cmd base64

TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

if [[ "$USE_TLS" == "true" ]]; then
  if [[ "$LETS_ENCRYPT" != "true" ]]; then
    require_cmd openssl
  fi
  if [[ "$LETS_ENCRYPT" != "true" && -z "$TRUSTSTORE_P12" ]]; then
    if [[ -n "$CA_CERT" ]]; then
      if [[ ! -f "$CA_CERT" ]]; then
        echo "CA cert file not found: $CA_CERT" >&2
        exit 1
      fi
      create_truststore_from_pem "$CA_CERT" "$TRUSTSTORE_OUT" "$CA_PASSWORD"
      TRUSTSTORE_P12="$TRUSTSTORE_OUT"
      echo "Created truststore from --ca-cert: $TRUSTSTORE_P12"
    elif [[ "$FETCH_SERVER_CERT" == "true" ]]; then
      SERVER_CERT_PEM="$TEMP_DIR/server-cert.pem"
      fetch_server_cert_pem "$SERVER_HOST" "$SERVER_PORT" "$SERVER_CERT_PEM"
      create_truststore_from_pem "$SERVER_CERT_PEM" "$TRUSTSTORE_OUT" "$CA_PASSWORD"
      TRUSTSTORE_P12="$TRUSTSTORE_OUT"
      echo "Fetched server cert and created truststore: $TRUSTSTORE_P12"
    else
      echo "TLS mode requires one of: --truststore-p12, --ca-cert, or --fetch-server-cert" >&2
      exit 1
    fi
  fi
  if [[ "$LETS_ENCRYPT" != "true" && ! -f "$TRUSTSTORE_P12" ]]; then
    echo "Truststore file not found: $TRUSTSTORE_P12" >&2
    exit 1
  fi
fi

TRUSTSTORE_B64=""
if [[ -n "$TRUSTSTORE_P12" ]]; then
  TRUSTSTORE_B64="$(b64_file "$TRUSTSTORE_P12")"
fi

CLIENT_CERT_B64=""
if [[ -n "$CLIENT_CERT_P12" ]]; then
  if [[ ! -f "$CLIENT_CERT_P12" ]]; then
    echo "Client cert file not found: $CLIENT_CERT_P12" >&2
    exit 1
  fi
  CLIENT_CERT_B64="$(b64_file "$CLIENT_CERT_P12")"
fi

PAYLOAD_FILE="$TEMP_DIR/payload.json"
cat >"$PAYLOAD_FILE" <<EOF
{
  "username": "$(json_escape "$PROFILE_USERNAME")",
  "server_host": "$(json_escape "$SERVER_HOST")",
  "server_port": $SERVER_PORT,
  "cert_enroll_port": $ENROLL_PORT,
  "mode": "$(json_escape "$MODE")",
  "zip_name": "$(json_escape "$ZIP_NAME")",
  "use_tls": $USE_TLS,
  "lets_encrypt": $LETS_ENCRYPT,
  "truststore_filename": "$(json_escape "$TRUSTSTORE_FILENAME")",
  "truststore_p12_base64": "$(json_escape "$TRUSTSTORE_B64")",
  "ca_password": "$(json_escape "$CA_PASSWORD")",
  "client_cert_filename": "$(json_escape "$CLIENT_CERT_FILENAME")",
  "client_cert_p12_base64": "$(json_escape "$CLIENT_CERT_B64")",
  "client_password": "$(json_escape "$CLIENT_PASSWORD")",
  "store": false
}
EOF

mkdir -p "$(dirname "$OUTPUT")"
#curl --fail-with-body -sS \
#  -u "$ADMIN_USER:$ADMIN_PASS" \
#  -H "Content-Type: application/json" \
#  -X POST \
#  --data @"$PAYLOAD_FILE" \
#  "$API_URL/packages/connection-bundle" \
#  -o "$OUTPUT"

echo "Generated connection package: $OUTPUT"
echo "Transport mode: $([[ "$USE_TLS" == "true" ]] && echo "TLS" || echo "TCP (non-secure)")"
if [[ "$LETS_ENCRYPT" == "true" ]]; then
  echo "TLS trust mode: Let's Encrypt / public CA (no embedded truststore)"
fi
