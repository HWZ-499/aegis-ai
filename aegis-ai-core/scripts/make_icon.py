"""Generate a minimal 128x128 PNG for the extension icon."""
import struct
import zlib
from pathlib import Path

def make_chunk(ctype: str, data: bytes) -> bytes:
    chunk_type = ctype.encode("ascii")
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

sig = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
ihdr = make_chunk("IHDR", struct.pack(">IIBBBBB", 128, 128, 8, 2, 0, 0, 0))
raw = bytes([30, 30, 46] * (128 * 128))  # RGB (30,30,46) theme color
idat = make_chunk("IDAT", zlib.compress(raw, 9))
iend = make_chunk("IEND", b"")

out = Path(__file__).resolve().parent.parent.parent / "aegis-vscode" / "images" / "icon.png"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(sig + ihdr + idat + iend)
print("Written", out)
