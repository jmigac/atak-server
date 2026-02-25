from __future__ import annotations

import io


def render_qr_png(data: str, box_size: int = 8, border: int = 2) -> bytes:
    try:
        import qrcode
    except ImportError as exc:
        raise RuntimeError("qrcode dependency is not installed") from exc

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
