import base64
import sys

from provity.icons import _decode_icon_from_db, _encode_icon_for_db, _extract_app_icon


class _Upload:
    def __init__(self, name: str, data: bytes):
        self.name = name
        self._data = data

    def getvalue(self) -> bytes:
        return self._data


def test_encode_decode_roundtrip_png():
    # Minimal PNG header + IHDR-ish payload is enough for our b64 roundtrip test.
    png = b"\x89PNG\r\n\x1a\n" + b"dummy"

    b64, mime = _encode_icon_for_db(png, "image/png")
    assert mime == "image/png"
    assert b64

    decoded, decoded_mime = _decode_icon_from_db(icon_b64=b64, icon_b64_mime=mime)
    assert decoded == png
    assert decoded_mime == "image/png"


def test_extract_icon_from_ico_upload():
    up = _Upload("x.ico", b"ICO_BYTES")
    raw, mime = _extract_app_icon(up)
    assert raw == b"ICO_BYTES"
    assert mime == "image/x-icon"


def test_extract_icon_from_pe_prefers_png_payload(monkeypatch):
    # Build a fake pefile module that returns a PE with RT_ICON bytes that are PNG.
    png_payload = b"\x89PNG\r\n\x1a\n" + b"payload"

    class _Struct:
        def __init__(self, off: int, size: int):
            self.OffsetToData = off
            self.Size = size

    class _DataEntry:
        def __init__(self, off: int, size: int):
            self.struct = _Struct(off, size)

    class _Dir:
        def __init__(self, entries):
            self.entries = entries

    class _Entry:
        def __init__(self, entry_id=None, directory=None, data=None):
            self.id = entry_id
            self.directory = directory
            self.data = data

    class _PE:
        def __init__(self, path, fast_load=True):
            # memory mapped image with group entry at 10 and icon bytes at 100
            mm = bytearray(256)

            # GRPICONDIR (6 bytes) + 1 entry (14 bytes)
            # reserved=0, type=1, count=1
            grp = bytearray()
            grp += (0).to_bytes(2, "little")
            grp += (1).to_bytes(2, "little")
            grp += (1).to_bytes(2, "little")
            # width=0 (means 256), height=0, color=0, reserved=0
            grp += bytes([0, 0, 0, 0])
            # planes=0, bitcount=0 (forces our defaulting logic), bytesInRes=ignored here
            grp += (0).to_bytes(2, "little")
            grp += (0).to_bytes(2, "little")
            grp += (len(png_payload)).to_bytes(4, "little")
            # id=1
            grp += (1).to_bytes(2, "little")

            mm[10 : 10 + len(grp)] = grp
            mm[100 : 100 + len(png_payload)] = png_payload
            self._mm = bytes(mm)

            # Build resource tree
            RT_ICON = 3
            RT_GROUP_ICON = 14

            icon_lang = _DataEntry(100, len(png_payload))
            icon_leaf = _Entry(entry_id=1, directory=_Dir([_Entry(data=icon_lang)]))
            icon_type = _Entry(entry_id=RT_ICON, directory=_Dir([icon_leaf]))

            grp_lang = _DataEntry(10, len(grp))
            grp_leaf = _Entry(entry_id=1, directory=_Dir([_Entry(data=grp_lang)]))
            grp_type = _Entry(entry_id=RT_GROUP_ICON, directory=_Dir([grp_leaf]))

            self.DIRECTORY_ENTRY_RESOURCE = _Dir([icon_type, grp_type])

        def parse_data_directories(self, directories=None):
            return None

        def get_memory_mapped_image(self):
            return self._mm

    class _FakePefile:
        RESOURCE_TYPE = {"RT_ICON": 3, "RT_GROUP_ICON": 14}
        DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_RESOURCE": 2}

        PE = _PE

    monkeypatch.setitem(sys.modules, "pefile", _FakePefile)

    up = _Upload("a.exe", b"MZ...fake")
    raw, mime = _extract_app_icon(up)
    assert raw and raw.startswith(b"\x89PNG\r\n\x1a\n")
    assert mime == "image/png"

    b64, b64_mime = _encode_icon_for_db(raw, mime)
    assert b64_mime == "image/png"
    assert base64.b64decode(b64) == raw
