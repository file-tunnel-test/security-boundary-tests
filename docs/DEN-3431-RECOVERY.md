# DEN-3431 preserved-source recovery

The two larger Python files in this branch are preserved byte-for-byte as
deterministic gzip/base64 fragments and loaded by small digest-checking wrappers.
This makes the locally validated implementation recoverable without truncation
or semantic rewriting.

| Logical source | Recovery directory | Uncompressed bytes | SHA-256 |
|---|---|---:|---|
| `src/deep_tests/encrypted_object_model.py` | `src/deep_tests/.den3431/encrypted_object_model.py.gz.b64/` | 42,578 | `f2e4ab259bb6a9872e1e189f16655ce9e535636d063e21301e38082a7578d847` |
| `tests/test_den_3431_encrypted_objects.py` | `tests/.den3431/test_den_3431_encrypted_objects.py.gz.b64/` | 18,725 | `a20c15415bb79affe201e9eb6d76def16a28bd1a83bf8bf43690b14f44f119bf` |

Each wrapper concatenates the sorted `part*.txt` files, validates strict base64,
decompresses the deterministic gzip payload, verifies the uncompressed SHA-256,
and executes the recovered module. A digest mismatch fails closed before any
certification code or tests run.

The complete recovery layout was validated with Python compilation, all 17
DEN-3431 tests, two deterministic evidence renders, and a byte comparison
against `evidence/den-3431-certification.json`.
