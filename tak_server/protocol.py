from __future__ import annotations

from dataclasses import dataclass


WIRE_DELIMITED = "delimited"
WIRE_VARINT = "varint"


@dataclass(frozen=True)
class DecodedFrame:
    payload: bytes
    wire_format: str


def _decode_varint(buffer: bytes, start: int = 0) -> tuple[int, int] | None:
    shift = 0
    value = 0
    index = start
    while index < len(buffer):
        byte = buffer[index]
        value |= (byte & 0x7F) << shift
        index += 1
        if (byte & 0x80) == 0:
            return value, index
        shift += 7
        if shift > 35:
            return None
    return None


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint value must be non-negative")
    out = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            break
    return bytes(out)


def encode_for_wire(payload: bytes, wire_format: str) -> bytes:
    if wire_format == WIRE_VARINT:
        return encode_varint(len(payload)) + payload
    return payload + b"\n"


def extract_cot_xml(payload: bytes) -> bytes | None:
    trimmed = payload.strip()
    if not trimmed:
        return None
    if trimmed.startswith(b"<event") and b"</event>" in trimmed:
        start = trimmed.find(b"<event")
        end = trimmed.rfind(b"</event>")
        if start >= 0 and end >= 0:
            return trimmed[start : end + len(b"</event>")]

    # TAK protobuf payloads often carry CoT XML string fields; pull embedded XML.
    start = payload.find(b"<event")
    if start < 0:
        return None
    end = payload.find(b"</event>", start)
    if end < 0:
        return None
    return payload[start : end + len(b"</event>")]


class FrameParser:
    def __init__(self, max_frame_bytes: int = 1024 * 1024) -> None:
        self._buffer = b""
        self._max_frame_bytes = max_frame_bytes
        self._wire_format: str | None = None

    @property
    def wire_format(self) -> str:
        return self._wire_format or WIRE_DELIMITED

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    def push(self, chunk: bytes) -> list[DecodedFrame]:
        self._buffer += chunk
        frames: list[DecodedFrame] = []

        while True:
            if self._wire_format == WIRE_DELIMITED:
                decoded = self._parse_delimited()
            elif self._wire_format == WIRE_VARINT:
                decoded = self._parse_varint()
            else:
                decoded = self._parse_unknown()
            if decoded is None:
                break
            frames.append(decoded)

        return frames

    def _parse_unknown(self) -> DecodedFrame | None:
        if self._looks_textual():
            xml_frame = self._try_parse_xml_event_frame()
            if xml_frame is not None:
                frame, consume = xml_frame
                self._wire_format = WIRE_DELIMITED
                self._buffer = self._buffer[consume:]
                return frame

            delimited = self._try_parse_delimited_frame()
            if delimited is not None:
                self._wire_format = WIRE_DELIMITED
                self._consume_delimited()
                return delimited

            control = self._try_parse_control_frame_without_delimiter()
            if control is not None:
                self._wire_format = WIRE_DELIMITED
                self._buffer = b""
                return control

        varint = self._try_parse_varint_frame()
        if varint is not None:
            self._wire_format = WIRE_VARINT
            self._consume_varint()
            return varint

        return None

    def _parse_delimited(self) -> DecodedFrame | None:
        frame = self._try_parse_delimited_frame()
        if frame is None:
            return None
        self._consume_delimited()
        return frame

    def _parse_varint(self) -> DecodedFrame | None:
        frame = self._try_parse_varint_frame()
        if frame is None:
            return None
        self._consume_varint()
        return frame

    def _try_parse_delimited_frame(self) -> DecodedFrame | None:
        indexes = []
        for separator in (b"\n", b"\x00"):
            idx = self._buffer.find(separator)
            if idx >= 0:
                indexes.append(idx)
        if not indexes:
            return None
        split_at = min(indexes)
        payload = self._buffer[:split_at].strip()
        return DecodedFrame(payload=payload, wire_format=WIRE_DELIMITED)

    def _looks_textual(self) -> bool:
        sample = self._buffer[:64]
        if not sample:
            return False
        for byte in sample:
            if byte in (0x09, 0x0A, 0x0D):
                continue
            if 0x20 <= byte <= 0x7E:
                continue
            return False
        return True

    def _try_parse_xml_event_frame(self) -> tuple[DecodedFrame, int] | None:
        if not self._buffer:
            return None
        leading = len(self._buffer) - len(self._buffer.lstrip())
        candidate = self._buffer[leading:]
        start = candidate.find(b"<event")
        if start < 0:
            return None
        end = candidate.find(b"</event>", start)
        if end < 0:
            return None
        end_index = end + len(b"</event>")
        payload = candidate[start:end_index]
        consume = leading + end_index
        while consume < len(self._buffer) and self._buffer[consume : consume + 1] in {
            b"\n",
            b"\r",
            b"\x00",
        }:
            consume += 1
        return DecodedFrame(payload=payload, wire_format=WIRE_DELIMITED), consume

    def _try_parse_control_frame_without_delimiter(self) -> DecodedFrame | None:
        if not self._buffer or len(self._buffer) > 512:
            return None
        text = self._buffer.decode("utf-8", errors="ignore").strip()
        if not text:
            return None
        upper = text.upper()
        if upper.startswith("AUTH") or upper.startswith("AUTH_TOKEN") or upper in {
            "PING",
            "PING_REQUEST",
            "HEARTBEAT",
        }:
            return DecodedFrame(payload=text.encode("utf-8"), wire_format=WIRE_DELIMITED)
        return None

    def _consume_delimited(self) -> None:
        indexes = []
        for separator in (b"\n", b"\x00"):
            idx = self._buffer.find(separator)
            if idx >= 0:
                indexes.append(idx)
        if not indexes:
            return
        split_at = min(indexes)
        self._buffer = self._buffer[split_at + 1 :]

    def _try_parse_varint_frame(self) -> DecodedFrame | None:
        parsed = _decode_varint(self._buffer, 0)
        if parsed is None:
            return None
        length, start = parsed
        if length <= 0:
            return DecodedFrame(payload=b"", wire_format=WIRE_VARINT)
        if length > self._max_frame_bytes:
            raise ValueError(f"frame length too large: {length}")
        end = start + length
        if len(self._buffer) < end:
            return None
        payload = self._buffer[start:end]
        return DecodedFrame(payload=payload, wire_format=WIRE_VARINT)

    def _consume_varint(self) -> None:
        parsed = _decode_varint(self._buffer, 0)
        if parsed is None:
            return
        length, start = parsed
        if length <= 0:
            self._buffer = self._buffer[start:]
            return
        self._buffer = self._buffer[start + length :]
