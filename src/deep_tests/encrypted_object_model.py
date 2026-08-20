"""Loads the exact preserved DEN-3431 reference model from deterministic recovery fragments."""
from __future__ import annotations

import base64
import gzip
import hashlib
from pathlib import Path

_PARTS_DIR = Path(__file__).with_name(".den3431") / "encrypted_object_model.py.gz.b64"
_PAYLOAD = gzip.decompress(
    base64.b64decode(
        "".join(
            part.read_text(encoding="ascii").strip()
            for part in sorted(_PARTS_DIR.glob("part*.txt"))
        ),
        validate=True,
    )
)
_EXPECTED_SHA256 = "f2e4ab259bb6a9872e1e189f16655ce9e535636d063e21301e38082a7578d847"
if hashlib.sha256(_PAYLOAD).hexdigest() != _EXPECTED_SHA256:
    raise RuntimeError("DEN-3431 encrypted-object model recovery digest mismatch")
exec(
    compile(_PAYLOAD, str(Path(__file__).with_suffix(".preserved.py")), "exec"),
    globals(),
    globals(),
)
