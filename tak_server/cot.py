from __future__ import annotations

from dataclasses import dataclass
import xml.etree.ElementTree as ET


class CoTValidationError(ValueError):
    pass


REQUIRED_EVENT_ATTRIBUTES = ("uid", "type", "time", "stale")
REQUIRED_POINT_ATTRIBUTES = ("lat", "lon")


@dataclass(frozen=True)
class CoTEvent:
    raw: bytes
    uid: str
    cot_type: str
    time: str
    stale: str
    lat: float
    lon: float
    target_group: str | None


def parse_cot_event(raw: bytes) -> CoTEvent:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise CoTValidationError(f"invalid XML: {exc}") from exc

    if root.tag != "event":
        raise CoTValidationError("root element must be <event>")

    for attr in REQUIRED_EVENT_ATTRIBUTES:
        if not root.attrib.get(attr):
            raise CoTValidationError(f"missing event attribute: {attr}")

    point = root.find("point")
    if point is None:
        raise CoTValidationError("missing <point> element")

    for attr in REQUIRED_POINT_ATTRIBUTES:
        value = point.attrib.get(attr)
        if value is None:
            raise CoTValidationError(f"missing point attribute: {attr}")
        try:
            float(value)
        except ValueError as exc:
            raise CoTValidationError(f"invalid numeric point attribute: {attr}") from exc

    detail = root.find("detail")
    target_group = None
    if detail is not None:
        group = detail.find("__group")
        if group is not None:
            group_name = group.attrib.get("name")
            if group_name:
                target_group = group_name

    return CoTEvent(
        raw=raw,
        uid=str(root.attrib["uid"]),
        cot_type=str(root.attrib["type"]),
        time=str(root.attrib["time"]),
        stale=str(root.attrib["stale"]),
        lat=float(point.attrib["lat"]),
        lon=float(point.attrib["lon"]),
        target_group=target_group,
    )


def validate_cot_xml(raw: bytes) -> None:
    parse_cot_event(raw)
