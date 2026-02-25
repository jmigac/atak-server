#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from pathlib import Path
import sys

# Ensure repository root is importable when running the script directly.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tak_server.datapackage_builder import (
    ConnectionDataPackageRequest,
    build_connection_datapackage_zip,
)


def _b64_file(path: str | None) -> str | None:
    if not path:
        return None
    data = Path(path).read_bytes()
    return base64.b64encode(data).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate TAK/iTAK connection data package ZIP."
    )
    parser.add_argument("--host", required=True, help="TAK server hostname or IP")
    parser.add_argument("--port", type=int, default=8087, help="TAK server port")
    parser.add_argument("--username", default="operator", help="Profile username label")
    parser.add_argument("--mode", choices=["itak", "atak"], default="itak")
    parser.add_argument("--zip-name", default="tak-connection-package")
    parser.add_argument("--output", required=True, help="Output .zip file path")
    parser.add_argument(
        "--use-tls",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use TLS in generated connection profile",
    )
    parser.add_argument("--truststore-p12", help="Path to truststore .p12")
    parser.add_argument(
        "--truststore-filename",
        default="truststore-YOUR-CA.p12",
        help="File name to embed in ZIP",
    )
    parser.add_argument("--client-cert-p12", help="Path to user/client certificate .p12")
    parser.add_argument("--client-cert-filename", help="Embedded client cert file name")
    parser.add_argument("--ca-password", default="atakatak")
    parser.add_argument("--client-password", default="atakatak")
    args = parser.parse_args()

    package = build_connection_datapackage_zip(
        ConnectionDataPackageRequest(
            username=args.username,
            server_host=args.host,
            server_port=args.port,
            use_tls=bool(args.use_tls),
            mode=args.mode,
            zip_name=args.zip_name,
            truststore_filename=args.truststore_filename,
            truststore_p12_base64=_b64_file(args.truststore_p12),
            client_cert_filename=args.client_cert_filename,
            client_cert_p12_base64=_b64_file(args.client_cert_p12),
            ca_password=args.ca_password,
            client_password=args.client_password,
        )
    )

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(package.content)
    print(f"Wrote {out} ({len(package.content)} bytes), mode={package.mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
