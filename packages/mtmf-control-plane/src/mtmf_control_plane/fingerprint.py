"""Canonical PR 24P operator mutation fingerprint."""

from __future__ import annotations

import hashlib
import struct
import uuid

_DOMAIN = b"mtmf.pr24p.operator.v1"


def mutation_fingerprint(
    *,
    operation: str,
    identity_id: uuid.UUID,
    principal_id: uuid.UUID,
    issuer: str,
    subject: str,
    application_id: uuid.UUID,
    entitlement_id: uuid.UUID,
    quota_total: int | None,
    reason: str,
) -> bytes:
    """Return the exact 32-byte SHA-256 fingerprint from approved §6."""
    fields: list[bytes] = [
        _DOMAIN,
        operation.encode("utf-8"),
        identity_id.bytes,
        principal_id.bytes,
        issuer.encode("utf-8"),
        subject.encode("utf-8"),
        application_id.bytes,
        entitlement_id.bytes,
    ]
    if quota_total is None:
        fields.append(b"")
    else:
        fields.append(struct.pack(">q", quota_total))
    fields.append(reason.encode("utf-8"))
    encoded = b"".join(struct.pack(">I", len(field)) + field for field in fields)
    return hashlib.sha256(encoded).digest()
