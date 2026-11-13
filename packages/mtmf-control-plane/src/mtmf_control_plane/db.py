"""Narrow PostgreSQL adapter for the five private control functions."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

import psycopg


class ControlDatabaseError(Exception):
    """A safe private database failure; never an authorization ALLOW."""


def control_dsn_from_env() -> str:
    """Read the worker-only control DSN; never log or synthesize it."""
    value = os.environ.get("MTMF_CONTROL_DATABASE_URL", "").strip()
    if not value:
        raise ControlDatabaseError("MTMF_CONTROL_DATABASE_URL is not configured")
    return value


class ControlDatabase:
    """Sql-function adapter; callers own transaction boundaries."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    @contextmanager
    def transaction(self) -> Iterator[psycopg.Connection[tuple[object, ...]]]:
        """Open one READ COMMITTED control transaction and commit once."""
        with psycopg.connect(self._dsn) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            yield connection
            connection.commit()

    @staticmethod
    def _json(row: tuple[object, ...] | None) -> Mapping[str, object]:
        if row is None or row[0] is None:
            raise ControlDatabaseError("control function returned no result")
        value = row[0]
        loaded = json.loads(value) if isinstance(value, str) else value
        if not isinstance(loaded, dict):
            raise ControlDatabaseError("control function returned a non-object result")
        return loaded

    def snapshot(
        self,
        connection: psycopg.Connection[tuple[object, ...]],
        *,
        identity_id: uuid.UUID,
        principal_id: uuid.UUID,
        issuer: str,
        subject: str,
        application_id: uuid.UUID,
        entitlement_id: uuid.UUID | None,
    ) -> Mapping[str, object]:
        row = connection.execute(
            "SELECT mtmf.control_operator_authorization_snapshot(%s,%s,%s,%s,%s,%s)",
            (identity_id, principal_id, issuer, subject, application_id, entitlement_id),
        ).fetchone()
        return self._json(row)

    def grant(
        self,
        connection: psycopg.Connection[tuple[object, ...]],
        *,
        identity_id: uuid.UUID,
        principal_id: uuid.UUID,
        issuer: str,
        subject: str,
        application_id: uuid.UUID,
        entitlement_id: uuid.UUID,
        quota_total: int,
        reason: str,
        operation_id: uuid.UUID,
        fingerprint: bytes,
    ) -> Mapping[str, object]:
        row = connection.execute(
            "SELECT mtmf.control_entitlement_grant(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                identity_id,
                principal_id,
                issuer,
                subject,
                application_id,
                entitlement_id,
                quota_total,
                reason,
                operation_id,
                fingerprint,
            ),
        ).fetchone()
        return self._json(row)

    def revoke(
        self,
        connection: psycopg.Connection[tuple[object, ...]],
        *,
        identity_id: uuid.UUID,
        principal_id: uuid.UUID,
        issuer: str,
        subject: str,
        application_id: uuid.UUID,
        entitlement_id: uuid.UUID,
        reason: str,
        operation_id: uuid.UUID,
        fingerprint: bytes,
    ) -> Mapping[str, object]:
        row = connection.execute(
            "SELECT mtmf.control_entitlement_revoke(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                identity_id,
                principal_id,
                issuer,
                subject,
                application_id,
                entitlement_id,
                reason,
                operation_id,
                fingerprint,
            ),
        ).fetchone()
        return self._json(row)

    def get(
        self,
        connection: psycopg.Connection[tuple[object, ...]],
        *,
        identity_id: uuid.UUID,
        principal_id: uuid.UUID,
        issuer: str,
        subject: str,
        application_id: uuid.UUID,
        entitlement_id: uuid.UUID,
    ) -> Mapping[str, object]:
        row = connection.execute(
            "SELECT mtmf.control_entitlement_get(%s,%s,%s,%s,%s,%s)",
            (identity_id, principal_id, issuer, subject, application_id, entitlement_id),
        ).fetchone()
        return self._json(row)

    def admission_read(
        self, *, application_id: uuid.UUID, issuer: str, subject: str
    ) -> Mapping[str, object]:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                "SELECT mtmf.control_pre_tenant_admission_read(%s,%s,%s)",
                (application_id, issuer, subject),
            ).fetchone()
            return self._json(row)
