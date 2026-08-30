from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import hmac
import ipaddress
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping


class BoundaryViolation(ValueError):
    pass


def normalize_relative_path(value: str) -> str:
    decoded = urllib.parse.unquote(urllib.parse.unquote(value))
    if not decoded or "\x00" in decoded or "\\" in decoded or decoded.startswith("/"):
        raise BoundaryViolation("path must be a non-empty relative POSIX path")
    parts = PurePosixPath(decoded).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise BoundaryViolation("path traversal segment is forbidden")
    normalized = "/".join(parts)
    if normalized != decoded:
        raise BoundaryViolation("path normalization changed the request")
    return normalized


def validate_outbound_url(value: str, allowed_hosts: set[str]) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BoundaryViolation("outbound URL must use HTTPS without user info")
    host = parsed.hostname.rstrip(".").lower()
    if host not in {item.rstrip(".").lower() for item in allowed_hosts}:
        raise BoundaryViolation("outbound host is not allowlisted")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        raise BoundaryViolation("non-public IP destinations are forbidden")
    if parsed.fragment:
        raise BoundaryViolation("fragments are not sent upstream")
    return urllib.parse.urlunsplit(parsed)


def redact(value: str) -> str:
    token_pattern = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}")
    bearer_pattern = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+")
    redacted = token_pattern.sub("[REDACTED]", value)
    return bearer_pattern.sub(r"\1[REDACTED]", redacted)


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    roles: frozenset[str]


def authorize_read(principal: Principal, resource_tenant_id: str) -> None:
    if principal.tenant_id != resource_tenant_id:
        raise BoundaryViolation("cross-tenant read is forbidden")
    if not ({"reader", "admin"} & principal.roles):
        raise BoundaryViolation("read role is required")


def sign(secret: bytes, timestamp: int, nonce: str, body: bytes) -> str:
    message = f"{timestamp}.{nonce}.".encode() + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


@dataclass
class ReplayWindow:
    max_skew_seconds: int = 300
    seen: dict[str, int] = field(default_factory=dict)

    def verify(
        self,
        secret: bytes,
        timestamp: int,
        nonce: str,
        body: bytes,
        signature: str,
        now: int | None = None,
    ) -> None:
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > self.max_skew_seconds:
            raise BoundaryViolation("signature timestamp is outside the replay window")
        if nonce in self.seen:
            raise BoundaryViolation("nonce replay detected")
        expected = sign(secret, timestamp, nonce, body)
        if not hmac.compare_digest(expected, signature):
            raise BoundaryViolation("signature mismatch")
        self.seen[nonce] = timestamp
        cutoff = current - self.max_skew_seconds
        self.seen = {key: seen_at for key, seen_at in self.seen.items() if seen_at >= cutoff}


_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_PROXIMITY_FIELDS = {
    "shared_auth_step_up": frozenset(
        {
            "payload_type",
            "exchange_id",
            "recipient_device_fingerprint",
            "opaque_request_b64url",
            "expires_at",
        }
    ),
    "peer_info_offer": frozenset(
        {
            "payload_type",
            "transfer_id",
            "media_type",
            "content_size_bytes",
            "content_sha256",
            "content_b64url",
            "expires_at",
        }
    ),
    "update_manifest_offer": frozenset(
        {
            "payload_type",
            "application_id",
            "platform",
            "version",
            "distribution",
            "manifest_url",
            "manifest_sha256",
            "signature_algorithm",
            "signer_key_id",
            "manifest_signature_b64url",
            "expires_at",
        }
    ),
}


def validate_proximity_payload(
    payload: Mapping[str, Any], *, now: datetime.datetime
) -> None:
    payload_type = payload.get("payload_type")
    expected_fields = _PROXIMITY_FIELDS.get(payload_type)
    if expected_fields is None or frozenset(payload) != expected_fields:
        raise BoundaryViolation("unknown payload type or non-canonical fields")
    if _parse_expiry(payload["expires_at"]) <= now.astimezone(datetime.timezone.utc):
        raise BoundaryViolation("proximity payload expired")

    if payload_type == "shared_auth_step_up":
        fingerprint = payload["recipient_device_fingerprint"]
        opaque = payload["opaque_request_b64url"]
        if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
            raise BoundaryViolation("recipient fingerprint must be SHA-256")
        if not isinstance(opaque, str) or not 1 <= len(opaque) <= 2731:
            raise BoundaryViolation("opaque Shared Auth request is not bounded")
        _decode_base64url(opaque)
        return

    if payload_type == "peer_info_offer":
        content = _decode_base64url(payload["content_b64url"])
        size = payload["content_size_bytes"]
        digest = payload["content_sha256"]
        if not isinstance(size, int) or not 1 <= size <= 32768 or len(content) != size:
            raise BoundaryViolation("peer content size is invalid")
        if not isinstance(digest, str) or not hmac.compare_digest(
            hashlib.sha256(content).hexdigest(), digest
        ):
            raise BoundaryViolation("peer content digest mismatch")
        return

    manifest_url = urllib.parse.urlsplit(payload["manifest_url"])
    if (
        manifest_url.scheme != "https"
        or not manifest_url.hostname
        or manifest_url.username
        or manifest_url.password
        or manifest_url.fragment
    ):
        raise BoundaryViolation("update manifest must be an HTTPS URL without credentials")
    if payload["platform"] not in {"android", "ios", "linux", "macos", "windows"}:
        raise BoundaryViolation("update manifest platform is not allowed")
    if payload["distribution"] not in {
        "app_store",
        "testflight",
        "play_store",
        "managed_distribution",
        "direct_signed_package",
    }:
        raise BoundaryViolation("update distribution is not allowed")
    manifest_digest = payload["manifest_sha256"]
    if not isinstance(manifest_digest, str) or not _SHA256.fullmatch(manifest_digest):
        raise BoundaryViolation("update manifest digest must be SHA-256")
    if payload["signature_algorithm"] != "ed25519":
        raise BoundaryViolation("update manifest signature algorithm is not allowed")
    signature = payload["manifest_signature_b64url"]
    if not isinstance(signature, str) or not 86 <= len(signature) <= 512:
        raise BoundaryViolation("update manifest signature is not bounded")
    _decode_base64url(signature)


@dataclass
class ProximityFrameWindow:
    session_id: str
    next_sequence: int = 1
    seen_nonces: set[str] = field(default_factory=set)

    def accept(
        self,
        *,
        session_id: str,
        sequence: int,
        nonce_b64url: str,
        ciphertext_b64url: str,
    ) -> None:
        if session_id != self.session_id:
            raise BoundaryViolation("frame belongs to another proximity session")
        if sequence != self.next_sequence:
            raise BoundaryViolation("frame is replayed or out of order")
        if nonce_b64url in self.seen_nonces:
            raise BoundaryViolation("frame nonce was reused")
        if len(nonce_b64url) != 16:
            raise BoundaryViolation("frame nonce must encode 12 bytes")
        _decode_base64url(nonce_b64url)
        if not 22 <= len(ciphertext_b64url) <= 49152:
            raise BoundaryViolation("frame ciphertext is not bounded")
        _decode_base64url(ciphertext_b64url)
        self.seen_nonces.add(nonce_b64url)
        self.next_sequence += 1


def _decode_base64url(value: Any) -> bytes:
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        raise BoundaryViolation("value is not unpadded base64url")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise BoundaryViolation("value is not valid base64url") from error


def _parse_expiry(value: Any) -> datetime.datetime:
    if not isinstance(value, str):
        raise BoundaryViolation("expiry must be an RFC3339 timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise BoundaryViolation("expiry must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise BoundaryViolation("expiry must include a timezone")
    return parsed.astimezone(datetime.timezone.utc)
