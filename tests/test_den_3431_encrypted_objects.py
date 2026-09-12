"""Loads the exact preserved DEN-3431 tests from deterministic recovery fragments."""
from __future__ import annotations

import base64
import gzip
import hashlib
from pathlib import Path

_PARTS_DIR = Path(__file__).with_name(".den3431") / "test_den_3431_encrypted_objects.py.gz.b64"
_PAYLOAD = gzip.decompress(
    base64.b64decode(
        "".join(
            part.read_text(encoding="ascii").strip()
            for part in sorted(_PARTS_DIR.glob("part*.txt"))
        ),
        validate=True,
    )
)
_EXPECTED_SHA256 = "a20c15415bb79affe201e9eb6d76def16a28bd1a83bf8bf43690b14f44f119bf"
if hashlib.sha256(_PAYLOAD).hexdigest() != _EXPECTED_SHA256:
    raise RuntimeError("DEN-3431 test recovery digest mismatch")
exec(
    compile(_PAYLOAD, str(Path(__file__).with_suffix(".preserved.py")), "exec"),
    globals(),
    globals(),
)
