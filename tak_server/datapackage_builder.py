from __future__ import annotations

import base64
import io
import uuid
import zipfile
from dataclasses import dataclass
from xml.sax.saxutils import escape


@dataclass(frozen=True)
class ConnectionDataPackageRequest:
    username: str
    server_host: str
    server_port: int = 8087
    use_tls: bool = True
    mode: str = "itak"
    zip_name: str = "tak-connection-package"
    truststore_filename: str = "truststore-YOUR-CA.p12"
    truststore_p12_base64: str | None = None
    client_cert_filename: str | None = None
    client_cert_p12_base64: str | None = None
    ca_password: str = "atakatak"
    client_password: str = "atakatak"


@dataclass(frozen=True)
class GeneratedConnectionDataPackage:
    file_name: str
    content: bytes
    mode: str
    include_client_cert: bool


def _safe_name(value: str, fallback: str) -> str:
    allowed = []
    for ch in value.strip():
        if ch.isalnum() or ch in {"-", "_", "."}:
            allowed.append(ch)
        else:
            allowed.append("-")
    text = "".join(allowed).strip("-_.")
    return text or fallback


def _decode_b64(value: str | None, field_name: str) -> bytes | None:
    if not value:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not valid base64") from exc


def _secure_pref(
    *,
    username: str,
    host: str,
    port: int,
    use_tls: bool,
    truststore_filename: str,
    ca_password: str,
    client_cert_filename: str | None,
    client_password: str,
) -> str:
    protocol = "ssl" if use_tls else "tcp"
    connect_string = f"{host}:{port}:{protocol}"
    if client_cert_filename and use_tls:
        return f"""<?xml version='1.0' encoding='ASCII' standalone='yes'?>
<preferences>
  <preference version="1" name="cot_streams">
    <entry key="count" class="class java.lang.Integer">1</entry>
    <entry key="description0" class="class java.lang.String">{escape(username)} @ TAK Server</entry>
    <entry key="enabled0" class="class java.lang.Boolean">true</entry>
    <entry key="connectString0" class="class java.lang.String">{escape(connect_string)}</entry>
  </preference>
  <preference version="1" name="com.atakmap.app_preferences">
    <entry key="caLocation" class="class java.lang.String">cert/{escape(truststore_filename)}</entry>
    <entry key="caPassword" class="class java.lang.String">{escape(ca_password)}</entry>
    <entry key="certificateLocation" class="class java.lang.String">cert/{escape(client_cert_filename)}</entry>
    <entry key="clientPassword" class="class java.lang.String">{escape(client_password)}</entry>
    <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>
  </preference>
</preferences>
"""

    if not use_tls:
        return f"""<?xml version='1.0' encoding='ASCII' standalone='yes'?>
<preferences>
  <preference version="1" name="cot_streams">
    <entry key="count" class="class java.lang.Integer">1</entry>
    <entry key="description0" class="class java.lang.String">{escape(username)} @ TAK Server</entry>
    <entry key="enabled0" class="class java.lang.Boolean">true</entry>
    <entry key="connectString0" class="class java.lang.String">{escape(connect_string)}</entry>
  </preference>
  <preference version="1" name="com.atakmap.app_preferences">
    <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>
  </preference>
</preferences>
"""

    return f"""<?xml version='1.0' encoding='ASCII' standalone='yes'?>
<preferences>
  <preference version="1" name="cot_streams">
    <entry key="count" class="class java.lang.Integer">1</entry>
    <entry key="description0" class="class java.lang.String">{escape(username)} @ TAK Server</entry>
    <entry key="enabled0" class="class java.lang.Boolean">true</entry>
    <entry key="connectString0" class="class java.lang.String">{escape(connect_string)}</entry>
    <entry key="caLocation0" class="class java.lang.String">cert/{escape(truststore_filename)}</entry>
    <entry key="caPassword0" class="class java.lang.String">{escape(ca_password)}</entry>
    <entry key="useAuth0" class="class java.lang.Boolean">true</entry>
    <entry key="cacheCreds0" class="class java.lang.String">Cache credentials</entry>
    <entry key="enrollForCertificateWithTrust0" class="class java.lang.Boolean">true</entry>
  </preference>
  <preference version="1" name="com.atakmap.app_preferences">
    <entry key="enrollForCertificateWithTrust0" class="class java.lang.Boolean">true</entry>
    <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>
  </preference>
</preferences>
"""


def _manifest_xml(
    *,
    username: str,
    truststore_filename: str | None,
    client_cert_filename: str | None,
) -> str:
    uid = str(uuid.uuid4())
    contents = []
    if truststore_filename:
        contents.append(f'<Content ignore="false" zipEntry="{escape(truststore_filename)}"/>')
    if client_cert_filename:
        contents.append(f'<Content ignore="false" zipEntry="{escape(client_cert_filename)}"/>')
    contents.append('<Content ignore="false" zipEntry="secure.pref"/>')
    contents_block = "\n    ".join(contents)
    return f"""<MissionPackageManifest version="2">
  <Configuration>
    <Parameter name="uid" value="{escape(uid)}"/>
    <Parameter name="name" value="{escape(username)}"/>
  </Configuration>
  <Contents>
    {contents_block}
  </Contents>
</MissionPackageManifest>
"""


def build_connection_datapackage_zip(
    request: ConnectionDataPackageRequest,
) -> GeneratedConnectionDataPackage:
    if not request.server_host.strip():
        raise ValueError("server_host is required")
    if request.server_port <= 0 or request.server_port > 65535:
        raise ValueError("server_port must be between 1 and 65535")

    mode = request.mode.strip().lower()
    if mode not in {"itak", "atak"}:
        raise ValueError("mode must be one of: itak, atak")

    username = _safe_name(request.username, "operator")
    zip_base = _safe_name(request.zip_name, "tak-connection-package")
    zip_name = zip_base if zip_base.lower().endswith(".zip") else f"{zip_base}.zip"
    truststore_name = _safe_name(request.truststore_filename, "truststore-YOUR-CA.p12")
    truststore_bytes = _decode_b64(request.truststore_p12_base64, "truststore_p12_base64")
    if request.use_tls and not truststore_bytes:
        raise ValueError("truststore_p12_base64 is required when use_tls=true")

    client_cert_name = None
    client_cert_bytes = _decode_b64(request.client_cert_p12_base64, "client_cert_p12_base64")
    if client_cert_bytes:
        client_cert_name = _safe_name(
            request.client_cert_filename or f"{username}.p12",
            f"{username}.p12",
        )

    pref_text = _secure_pref(
        username=username,
        host=request.server_host.strip(),
        port=request.server_port,
        use_tls=request.use_tls,
        truststore_filename=truststore_name,
        ca_password=request.ca_password,
        client_cert_filename=client_cert_name,
        client_password=request.client_password,
    )
    manifest = _manifest_xml(
        username=username,
        truststore_filename=truststore_name if truststore_bytes else None,
        client_cert_filename=client_cert_name if client_cert_bytes else None,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if mode == "itak":
            archive.writestr("config.pref", pref_text.encode("ascii", errors="ignore"))
            if truststore_bytes:
                archive.writestr(truststore_name, truststore_bytes)
            if client_cert_bytes and client_cert_name:
                archive.writestr(client_cert_name, client_cert_bytes)
        else:
            root = _safe_name(zip_base.replace(".zip", ""), "tak-connection-package")
            archive.writestr(f"{root}/secure.pref", pref_text.encode("ascii", errors="ignore"))
            archive.writestr(f"{root}/MANIFEST/manifest.xml", manifest.encode("utf-8"))
            if truststore_bytes:
                archive.writestr(f"{root}/{truststore_name}", truststore_bytes)
            if client_cert_bytes and client_cert_name:
                archive.writestr(f"{root}/{client_cert_name}", client_cert_bytes)

    return GeneratedConnectionDataPackage(
        file_name=zip_name,
        content=buffer.getvalue(),
        mode=mode,
        include_client_cert=bool(client_cert_bytes),
    )
