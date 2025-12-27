from __future__ import annotations

import base64
import os
import tempfile
from io import BytesIO
from pathlib import Path


def _debug_icon_pipeline(
    *,
    label: str,
    raw_bytes: bytes | None,
    raw_mime: str | None,
    b64: str | None,
    b64_mime: str | None,
) -> None:
    """Emit small, non-sensitive diagnostics for icon extraction.

    Enabled only when PROVITY_DEBUG_ICON=1.

    Notes:
      - Streamlit is imported lazily to avoid import-time overhead when debugging is off.
    """
    if os.getenv("PROVITY_DEBUG_ICON") != "1":
        return

    try:
        import streamlit as st  # type: ignore

        raw_len = len(raw_bytes) if raw_bytes else 0
        b64_len = len(b64) if b64 else 0
        st.sidebar.caption(
            f"[icon] {label}: raw_len={raw_len} raw_mime={raw_mime or 'n/a'} → b64_len={b64_len} b64_mime={b64_mime or 'n/a'}"
        )
    except Exception:
        pass


def _decode_icon_from_db(*, icon_b64: str | None, icon_b64_mime: str | None) -> tuple[bytes | None, str | None]:
    """Decode icon from base64 DB fields (base64-only)."""
    if not icon_b64:
        return None, None
    try:
        return base64.b64decode(icon_b64), (icon_b64_mime or "image/png")
    except Exception:
        return None, None


def _ico_bytes_to_png_bytes(ico_bytes: bytes) -> bytes | None:
    """Convert .ico bytes to PNG bytes (best-effort).

    Streamlit can be picky with some .ico variants; converting to PNG improves reliability.
    If Pillow isn't available or conversion fails, return None.
    """
    if not ico_bytes:
        return None

    try:
        from PIL import Image  # type: ignore

        im = Image.open(BytesIO(ico_bytes))
        # ICO can contain multiple sizes; pick the largest.
        try:
            n = getattr(im, "n_frames", 1)
        except Exception:
            n = 1

        best = None
        best_area = -1
        for i in range(max(1, n)):
            try:
                im.seek(i)
            except Exception:
                break
            w, h = im.size
            if w * h > best_area:
                best_area = w * h
                best = im.copy()

        if best is None:
            best = im

        if best.mode not in ("RGBA", "RGB"):
            best = best.convert("RGBA")

        out = BytesIO()
        best.save(out, format="PNG")
        return out.getvalue()
    except Exception:
        return None


def _image_bytes_to_png_bytes(image_bytes: bytes, mime: str | None) -> bytes | None:
    """Convert various image bytes to PNG (best-effort).

    We primarily see ICO; PNG is passed through; other formats try Pillow.
    """
    if not image_bytes:
        return None
    if mime == "image/png":
        return image_bytes
    if mime in ("image/x-icon", "image/vnd.microsoft.icon"):
        return _ico_bytes_to_png_bytes(image_bytes)

    try:
        from PIL import Image  # type: ignore

        im = Image.open(BytesIO(image_bytes))
        if im.mode not in ("RGBA", "RGB"):
            im = im.convert("RGBA")
        out = BytesIO()
        im.save(out, format="PNG")
        return out.getvalue()
    except Exception:
        return None


def _encode_icon_for_db(icon_bytes: bytes | None, icon_mime: str | None) -> tuple[str | None, str | None]:
    """Return (b64, mime) to store in DB.

    We store PNG bytes as base64 (most reliable to render in Streamlit).
    """
    if not icon_bytes:
        return None, None

    png_bytes = _image_bytes_to_png_bytes(icon_bytes, icon_mime)
    if png_bytes:
        return base64.b64encode(png_bytes).decode("ascii"), "image/png"

    # Fallback: store original bytes.
    try:
        return base64.b64encode(icon_bytes).decode("ascii"), icon_mime
    except Exception:
        return None, None


def _extract_app_icon(uploaded_file) -> tuple[bytes | None, str | None]:
    """Best-effort icon extraction.

    Currently supported:
      - .ico uploads: stored as-is.

    Best-effort support:
      - Windows binaries (.exe/.dll/.sys): extract the first icon via pefile.

    Notes:
      - Streamlit is imported lazily (only when PROVITY_DEBUG_ICON=1).
      - pefile is imported lazily (only for Windows binaries).
    """
    try:
        name = getattr(uploaded_file, "name", "") or ""
        debug = os.getenv("PROVITY_DEBUG_ICON") == "1"

        st = None
        if debug:
            try:
                import streamlit as _st  # type: ignore

                st = _st
                st.sidebar.caption(f"[icon] start extract name={name!r}")
            except Exception:
                st = None

        if name.lower().endswith(".ico"):
            raw = uploaded_file.getvalue()
            if raw:
                return raw, "image/x-icon"

        if not name.lower().endswith((".exe", ".dll", ".sys")):
            return None, None

        import pefile  # type: ignore

        data = uploaded_file.getvalue()
        if not data:
            if st is not None:
                try:
                    st.sidebar.caption("[icon] empty upload bytes")
                except Exception:
                    pass
            return None, None

        def _best_icon_bytes_from_pe(pe: "pefile.PE") -> tuple[bytes | None, str | None]:
            RT_ICON = pefile.RESOURCE_TYPE["RT_ICON"]
            RT_GROUP_ICON = pefile.RESOURCE_TYPE["RT_GROUP_ICON"]

            if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                return None

            # Collect RT_ICON images by integer ID.
            icon_images: dict[int, bytes] = {}
            group_entries: list[bytes] = []

            mm = pe.get_memory_mapped_image()
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.id == RT_ICON:
                    for e2 in entry.directory.entries:
                        icon_id = int(e2.id)
                        lang_entry = e2.directory.entries[0]
                        data_rva = lang_entry.data.struct.OffsetToData
                        size = lang_entry.data.struct.Size
                        icon_images[icon_id] = mm[data_rva : data_rva + size]
                elif entry.id == RT_GROUP_ICON:
                    for e2 in entry.directory.entries:
                        lang_entry = e2.directory.entries[0]
                        data_rva = lang_entry.data.struct.OffsetToData
                        size = lang_entry.data.struct.Size
                        group_entries.append(mm[data_rva : data_rva + size])

            if not group_entries or not icon_images:
                return None

            grp = group_entries[0]
            if len(grp) < 6:
                return None

            reserved = int.from_bytes(grp[0:2], "little")
            typ = int.from_bytes(grp[2:4], "little")
            count = int.from_bytes(grp[4:6], "little")
            if reserved != 0 or typ != 1 or count <= 0:
                return None

            parsed: list[tuple[int, int, int, int, int, bytes]] = []
            off = 6
            for _ in range(count):
                if off + 14 > len(grp):
                    break
                entry14 = grp[off : off + 14]
                off += 14
                width = entry14[0]
                height = entry14[1]
                color_count = entry14[2]
                planes = int.from_bytes(entry14[4:6], "little")
                bit_count = int.from_bytes(entry14[6:8], "little")
                icon_id = int.from_bytes(entry14[12:14], "little")
                img = icon_images.get(icon_id)
                if img:
                    parsed.append((width, height, color_count, planes, bit_count, img))

            if not parsed:
                return None, None

            best = max(parsed, key=lambda x: (int(x[0] or 256) * int(x[1] or 256), len(x[5])))
            width, height, color_count, planes, bit_count, img = best

            # Many modern Windows binaries store icon images as raw PNG in RT_ICON.
            # Prefer returning the PNG bytes directly (Streamlit + Pillow handle this reliably).
            if img.startswith(b"\x89PNG\r\n\x1a\n"):
                return img, "image/png"

            out = bytearray()
            out += (0).to_bytes(2, "little")  # reserved
            out += (1).to_bytes(2, "little")  # type
            out += (1).to_bytes(2, "little")  # count

            img_offset = 6 + 16
            out += bytes([width, height, color_count, 0])

            # Some group icon entries can have 0 planes/bitcount for PNG payloads.
            # Use safe defaults so Pillow can parse the ICO wrapper if needed.
            planes_i = int(planes) if int(planes) > 0 else 1
            bit_count_i = int(bit_count) if int(bit_count) > 0 else 32
            out += planes_i.to_bytes(2, "little")
            out += bit_count_i.to_bytes(2, "little")
            out += int(len(img)).to_bytes(4, "little")
            out += int(img_offset).to_bytes(4, "little")
            out += img
            return bytes(out), "image/x-icon"

        # pefile prefers a file path.
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(name).suffix) as f:
            f.write(data)
            tmp = f.name

        try:
            pe = pefile.PE(tmp, fast_load=True)
            try:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            except Exception:
                pass

            icon_bytes, icon_mime = _best_icon_bytes_from_pe(pe)
            if icon_bytes:
                return icon_bytes, (icon_mime or "image/x-icon")

            if st is not None:
                try:
                    st.sidebar.caption("[icon] pefile found no icon resources")
                except Exception:
                    pass
            return None, None
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass

    except Exception as e:
        if os.getenv("PROVITY_DEBUG_ICON") == "1":
            try:
                import streamlit as st  # type: ignore

                st.sidebar.caption(f"[icon] extraction failed for {name}: {type(e).__name__}: {e}")
            except Exception:
                pass
        return None, None
