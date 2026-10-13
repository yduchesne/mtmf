"""Development-only Keycloak user provisioning and verification (PR 17-B).

This module owns the *verified-subject* step of the development one-shot
initializer. It is deliberately narrow:

- it parses an explicit, fail-closed :class:`DevUserConfig` from the
  environment (never the runtime ``ServiceSettings``);
- it looks up exactly one Keycloak user by configured username, filters the
  Admin REST result by exact username, and rejects ambiguous, disabled,
  federated, or drifted accounts;
- it creates the user only when creation is explicitly enabled, using a
  protected password file that is read only for creation; and
- it returns Keycloak's authoritative immutable user ID / OIDC ``sub``.

Keycloak owns authentication and the immutable subject. MTMF binds only the
subject actually returned by the trusted realm; ``MTMF_DEV_USER_SUBJECT`` is
an optional *assertion* and is never a fabricated identity source. This
module performs no MTMF persistence and never imports a database driver.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import time
import urllib.error
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from mtmf_service.development_bootstrap import BootstrapError

__all__ = [
    "DevUserConfig",
    "DevUserConfigurationError",
    "KeycloakAdminTransport",
    "KeycloakDevUserProvisioner",
    "load_dev_user_password",
]

#: Bounded credential file size. A development password is far smaller; the
#: bound prevents unbounded reads from a hostile or accidental path.
_MAX_PASSWORD_BYTES = 8192

#: Usernames longer than this are rejected before any lookup or mutation.
_MAX_USERNAME_LENGTH = 255

_EMAIL_AT = "@"


class DevUserConfigurationError(BootstrapError):
    """The development user configuration is missing, malformed, or unsafe."""


@runtime_checkable
class KeycloakAdminTransport(Protocol):
    """The narrow Admin REST seam the provisioner depends on.

    Implementations authenticate with their own privileged credential and
    return already-parsed JSON (``None`` for an empty body). Non-2xx
    responses raise :class:`urllib.error.HTTPError`; transport failures
    raise :class:`urllib.error.URLError`, :class:`TimeoutError`, or
    :class:`OSError`. The provisioner converts all of them into a redacted
    :class:`~mtmf_service.development_bootstrap.BootstrapError`.
    """

    def request(self, method: str, path: str, body: Any | None = None) -> Any:
        """Perform one Admin REST call and return parsed JSON (or ``None``)."""
        ...

    def create_user(self, path: str, body: Any) -> str | None:
        """POST a new user and return the authoritative created-resource location.

        Implementations raise the same transport exceptions as :meth:`request`
        and return Keycloak's ``Location`` header on success (whose final path
        segment is the created user's immutable id), or ``None`` when the
        authority does not provide one. The location is the creation provenance
        used to distinguish this invocation's create from an unrelated account.
        """
        ...


@dataclass(frozen=True, slots=True)
class DevUserConfig:
    """Validated, immutable development-user configuration.

    The settings are intentionally separate from the runtime
    ``ServiceSettings`` so the HTTP service can never receive development
    provisioning credentials or configuration.
    """

    username: str
    email: str | None
    create: bool
    password_file: Path | None
    expected_subject: str | None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> DevUserConfig:
        """Parse and validate the configuration before any external I/O.

        :raises DevUserConfigurationError: on a blank username, ambiguous
            canonicalization, an invalid boolean, an unsafe password path, or
            a whitespace-only expected-subject assertion.
        """
        source = os.environ if environ is None else environ
        return cls(
            username=_parse_username(source.get("MTMF_DEV_USER_USERNAME")),
            email=_parse_email(source.get("MTMF_DEV_USER_EMAIL")),
            create=_parse_bool(source.get("MTMF_DEV_USER_CREATE"), "MTMF_DEV_USER_CREATE"),
            password_file=_parse_password_file(source.get("MTMF_DEV_USER_PASSWORD_FILE")),
            expected_subject=_parse_expected_subject(source),
        )


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _parse_username(raw: str | None) -> str:
    if raw is None:
        raise DevUserConfigurationError("MTMF_DEV_USER_USERNAME is required")
    value = raw.strip()
    if not value:
        raise DevUserConfigurationError("MTMF_DEV_USER_USERNAME must be a non-empty username")
    if len(value) > _MAX_USERNAME_LENGTH:
        raise DevUserConfigurationError("MTMF_DEV_USER_USERNAME is too long")
    if _has_control_characters(value):
        raise DevUserConfigurationError(
            "MTMF_DEV_USER_USERNAME must not contain control characters"
        )
    if any(character in value for character in "/\\?#"):
        raise DevUserConfigurationError(
            "MTMF_DEV_USER_USERNAME must not contain URL-reserved characters"
        )
    if value != value.lower():
        raise DevUserConfigurationError(
            "MTMF_DEV_USER_USERNAME must use its canonical lowercase form"
        )
    return value


def _parse_email(raw: str | None) -> str | None:
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None
    if _has_control_characters(value) or " " in value:
        raise DevUserConfigurationError("MTMF_DEV_USER_EMAIL contains illegal characters")
    if value.count(_EMAIL_AT) != 1 or value.startswith(_EMAIL_AT) or value.endswith(_EMAIL_AT):
        raise DevUserConfigurationError("MTMF_DEV_USER_EMAIL is not a valid email address")
    return value


def _parse_bool(raw: str | None, name: str) -> bool:
    value = ("" if raw is None else raw).strip().lower()
    if value in ("", "false"):
        return False
    if value == "true":
        return True
    raise DevUserConfigurationError(f"{name} must be exactly 'true' or 'false'")


def _parse_password_file(raw: str | None) -> Path | None:
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None
    if _has_control_characters(value):
        raise DevUserConfigurationError("MTMF_DEV_USER_PASSWORD_FILE contains illegal characters")
    return Path(value)


def _parse_expected_subject(source: Mapping[str, str]) -> str | None:
    if "MTMF_DEV_USER_SUBJECT" not in source:
        return None
    raw = source["MTMF_DEV_USER_SUBJECT"]
    if raw == "":
        # An empty value is how Compose forwards an unset optional assertion.
        return None
    value = raw.strip()
    if not value:
        raise DevUserConfigurationError(
            "MTMF_DEV_USER_SUBJECT, when set, must be a non-empty subject"
        )
    if _has_control_characters(value) or any(character.isspace() for character in value):
        raise DevUserConfigurationError(
            "MTMF_DEV_USER_SUBJECT must not contain whitespace or control characters"
        )
    return value


def _read_bounded(descriptor: int) -> bytes:
    """Read at most ``_MAX_PASSWORD_BYTES + 1`` bytes from one open descriptor."""
    chunks: list[bytes] = []
    remaining = _MAX_PASSWORD_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def load_dev_user_password(path: Path | None) -> str:
    """Securely read a development password file for user creation only.

    The file is opened **once** with ``O_NOFOLLOW`` and validated with
    ``fstat`` on that same descriptor, so a pathname substitution between
    validation and read cannot be observed. The file must be an owner-only
    regular file (no symlink, FIFO, device, or directory; no group/other mode
    bits), bounded in size, valid UTF-8, and non-empty. The content is returned
    for immediate use and never logged.

    :raises DevUserConfigurationError: when the path is missing or unsafe.
    """
    if path is None:
        raise DevUserConfigurationError(
            "creation is enabled but MTMF_DEV_USER_PASSWORD_FILE is not configured"
        )
    if not hasattr(os, "O_NOFOLLOW"):
        raise DevUserConfigurationError(
            "this platform cannot open the development user password file without following "
            "symbolic links; refusing to read it"
        )
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise DevUserConfigurationError(
                "the development user password file must not be a symbolic link"
            ) from exc
        raise DevUserConfigurationError(
            "the development user password file is not readable"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise DevUserConfigurationError(
                "the development user password file must be a regular file"
            )
        if info.st_size <= 0:
            raise DevUserConfigurationError("the development user password file is empty")
        if info.st_size > _MAX_PASSWORD_BYTES:
            raise DevUserConfigurationError("the development user password file is too large")
        if info.st_mode & 0o077:
            raise DevUserConfigurationError(
                "the development user password file must not be group- or other-accessible"
            )
        if os.geteuid() != 0 and info.st_uid != os.geteuid():
            raise DevUserConfigurationError(
                "the development user password file must be owned by the initializer user"
            )
        raw = _read_bounded(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_PASSWORD_BYTES:
        raise DevUserConfigurationError("the development user password file is too large")
    if b"\x00" in raw:
        raise DevUserConfigurationError("the development user password file contains invalid bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DevUserConfigurationError(
            "the development user password file is not valid UTF-8"
        ) from exc
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text:
        raise DevUserConfigurationError("the development user password file is empty")
    return text


@dataclass(frozen=True, slots=True)
class _VerifiedUser:
    subject: str
    username: str
    enabled: bool
    email: str | None
    federated: bool


class _CreateOutcome(StrEnum):
    """How one bounded user-creation attempt concluded."""

    CREATED = "created"
    REJECTED = "rejected"
    CONFLICT = "conflict"
    INDETERMINATE = "indeterminate"


class KeycloakDevUserProvisioner:
    """Create or verify exactly one development Keycloak user.

    The provisioner never mutates an existing account: it only reads and
    validates. Creation happens once, only when explicitly enabled, and is
    always followed by a bounded authoritative re-read.
    """

    def __init__(
        self,
        transport: KeycloakAdminTransport,
        realm: str,
        *,
        admin_base_url: str | None = None,
        lookup_attempts: int = 3,
        retry_delay: float = 0.25,
    ) -> None:
        if not realm:
            raise DevUserConfigurationError("the Keycloak realm is required")
        if lookup_attempts < 1:
            raise DevUserConfigurationError("lookup_attempts must be positive")
        self._transport = transport
        self._realm = realm
        self._admin_base_url = admin_base_url
        self._lookup_attempts = lookup_attempts
        self._retry_delay = retry_delay

    def ensure_user(self, config: DevUserConfig) -> str:
        """Return the verified Keycloak user ID / OIDC ``sub``.

        Creation provenance is explicit and fail-closed: an existing account is
        reused read-only; a successful create is accepted only when the account
        read back matches Keycloak's own ``Location`` for that create; and a
        conflict or indeterminate outcome is accepted only when the operator
        asserted the expected subject. A definite rejection is never converted
        into a success by a later matching lookup.

        :raises BootstrapError: on a missing user with creation disabled, an
            ambiguous lookup, a disabled/federated/drifted account, an unsafe
            secret file, a rejected/uncertain creation without independent
            correlation, or a failed subject assertion. No MTMF state is touched.
        """
        matches = self._lookup_exact(config.username)
        if len(matches) > 1:
            raise BootstrapError(
                "multiple Keycloak users match the configured development username; "
                "refusing to select one"
            )
        if matches:
            return _bind_existing(matches[0], config)
        if not config.create:
            raise BootstrapError(
                "no Keycloak user matches the configured development username and "
                "creation is not enabled (MTMF_DEV_USER_CREATE)"
            )
        password = load_dev_user_password(config.password_file)
        outcome, location, detail = self._attempt_create(config, password)
        if outcome is _CreateOutcome.REJECTED:
            raise BootstrapError(
                "Keycloak rejected the development user creation; no MTMF binding was created"
                + (f" ({detail})" if detail else "")
            )
        matches = self._lookup_exact(config.username)
        if len(matches) != 1:
            raise BootstrapError(
                "the development Keycloak user could not be created or verified"
                + (f" ({detail})" if detail else "")
            )
        verified = _validate_user(matches[0])
        _verify_attributes(verified, config)
        if outcome is _CreateOutcome.CREATED:
            created_subject = _created_subject(location, self._realm, self._admin_base_url)
            if created_subject is None or created_subject != verified.subject:
                raise BootstrapError(
                    "Keycloak creation provenance could not be verified; "
                    "no MTMF identity binding was created"
                )
        elif config.expected_subject is None:
            raise BootstrapError(
                "the development Keycloak user was not verifiably created by this invocation "
                "(conflict or uncertain create outcome); rerun to reuse the existing account "
                "or provide MTMF_DEV_USER_SUBJECT to assert the expected subject"
            )
        if config.expected_subject is not None and config.expected_subject != verified.subject:
            raise BootstrapError(
                "the configured MTMF_DEV_USER_SUBJECT assertion does not match the "
                "Keycloak user ID; no MTMF binding was created"
            )
        return verified.subject

    # -- transport ---------------------------------------------------------
    def _lookup_exact(self, username: str) -> list[dict[str, Any]]:
        """Return exact-username user records, retrying only a transient zero.

        An ambiguous result is returned immediately; the caller decides. A
        zero result is retried a bounded number of times to tolerate a
        Keycloak read-after-write delay without ever selecting a fuzzy match.
        """
        quoted = urllib.parse.quote(username, safe="")
        path = f"/admin/realms/{self._realm}/users?username={quoted}&exact=true"
        for attempt in range(self._lookup_attempts):
            rows = self._read_rows(path)
            matches = [row for row in rows if _username_matches(row, username)]
            if matches or attempt == self._lookup_attempts - 1:
                return matches
            _sleep(self._retry_delay)
        return []

    def _read_rows(self, path: str) -> list[dict[str, Any]]:
        payload = self._call("GET", path)
        if payload is None:
            return []
        if not isinstance(payload, list):
            raise BootstrapError("the Keycloak user lookup returned an invalid response")
        rows: list[dict[str, Any]] = []
        for entry in payload:
            if not isinstance(entry, dict):
                raise BootstrapError("the Keycloak user lookup returned an invalid record")
            rows.append(entry)
        return rows

    def _attempt_create(
        self, config: DevUserConfig, password: str
    ) -> tuple[_CreateOutcome, str | None, str | None]:
        """Perform exactly one create POST and classify the outcome.

        Returns ``(outcome, location, redacted_detail)``. The caller performs
        the bounded authoritative re-read; this method never retries and never
        treats a definite rejection as success.
        """
        body: dict[str, Any] = {
            "username": config.username,
            "enabled": True,
            # Generic, non-identity profile names. The development realm's user
            # profile requires them, so supplying them lets a newly created user
            # sign in through the approved OIDC flow without a profile-update
            # detour and without weakening any realm or client policy.
            "firstName": "MTMF",
            "lastName": "Development User",
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        }
        if config.email is not None:
            body["email"] = config.email
            # The initializer has not proven control of this address, so it must
            # not claim the email is verified.
            body["emailVerified"] = False
        try:
            location = self._transport.create_user(f"/admin/realms/{self._realm}/users", body)
        except urllib.error.HTTPError as exc:
            return _classify_http_status(exc.code), None, f"Keycloak returned HTTP {exc.code}"
        except urllib.error.URLError, TimeoutError, OSError:
            return _CreateOutcome.INDETERMINATE, None, "the Keycloak request failed or timed out"
        except json.JSONDecodeError:
            return _CreateOutcome.INDETERMINATE, None, "the Keycloak response was malformed"
        return _CreateOutcome.CREATED, location, None

    def _call(self, method: str, path: str, body: Any | None = None) -> Any:
        try:
            return self._transport.request(method, path, body)
        except urllib.error.HTTPError as exc:
            raise BootstrapError(
                f"the Keycloak Admin REST {method} request failed with HTTP {exc.code}"
            ) from None
        except urllib.error.URLError, TimeoutError, OSError:
            raise BootstrapError(
                f"the Keycloak Admin REST {method} request could not be completed"
            ) from None
        except json.JSONDecodeError:
            raise BootstrapError("the Keycloak Admin REST response was malformed") from None


def _username_matches(row: Mapping[str, Any], username: str) -> bool:
    candidate = row.get("username")
    return isinstance(candidate, str) and candidate.casefold() == username.casefold()


def _validate_user(row: Mapping[str, Any]) -> _VerifiedUser:
    subject = row.get("id")
    username = row.get("username")
    if not isinstance(subject, str) or not subject.strip():
        raise BootstrapError("a Keycloak user record is missing its stable identifier")
    if not isinstance(username, str) or not username.strip():
        raise BootstrapError("a Keycloak user record is missing its username")
    enabled = row.get("enabled")
    if not isinstance(enabled, bool):
        raise BootstrapError("a Keycloak user record has an unverifiable enabled state")
    email = row.get("email")
    if email is not None and not isinstance(email, str):
        raise BootstrapError("a Keycloak user record has an invalid email value")
    federated = (
        bool(row.get("federationLink"))
        or bool(row.get("serviceAccountClientId"))
        or bool(row.get("origin"))
    )
    return _VerifiedUser(
        subject=subject.strip(),
        username=username.strip(),
        enabled=enabled,
        email=email,
        federated=federated,
    )


def _verify_attributes(verified: _VerifiedUser, config: DevUserConfig) -> None:
    if verified.federated:
        raise BootstrapError(
            "the configured development username resolves to a federated or managed account"
        )
    if not verified.enabled:
        raise BootstrapError("the configured development Keycloak user is disabled")
    if config.email is not None:
        existing = verified.email
        if existing is None or existing.strip().casefold() != config.email.casefold():
            raise BootstrapError(
                "the configured development Keycloak user email does not match; no repair "
                "is performed"
            )


def _bind_existing(row: Mapping[str, Any], config: DevUserConfig) -> str:
    """Validate and return the subject of an existing account (read-only)."""
    verified = _validate_user(row)
    _verify_attributes(verified, config)
    if config.expected_subject is not None and config.expected_subject != verified.subject:
        raise BootstrapError(
            "the configured MTMF_DEV_USER_SUBJECT assertion does not match the "
            "Keycloak user ID; no MTMF binding was created"
        )
    return verified.subject


def _classify_http_status(code: int) -> _CreateOutcome:
    """Classify a create-POST HTTP failure without claiming false certainty."""
    if code == 409:
        return _CreateOutcome.CONFLICT
    if 400 <= code < 500 and code != 408:
        return _CreateOutcome.REJECTED
    return _CreateOutcome.INDETERMINATE


def _created_subject(location: str | None, realm: str, admin_base_url: str | None) -> str | None:
    """Return the created immutable user id from a strict Keycloak ``Location``.

    Only an absolute location whose scheme and origin equal the configured
    trusted Keycloak admin base (HTTPS in production; the documented loopback
    test fault proxy is the only HTTP exception) and whose path is exactly
    ``/admin/realms/<configured-realm>/users/<id>`` is accepted. Missing,
    malformed, foreign-origin, wrong-realm, wrong-resource, encoded, or
    traversal-bearing locations return ``None`` so the caller fails closed.
    """
    if not isinstance(location, str):
        return None
    if _has_control_characters(location):
        return None
    value = location.strip()
    if not value or not realm:
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        trusted = urllib.parse.urlsplit(admin_base_url) if admin_base_url else None
    except ValueError:
        return None
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if parsed.query or parsed.fragment or "%" in parsed.path:
        return None
    if trusted is None or trusted.scheme not in ("https", "http") or not trusted.netloc:
        return None
    if parsed.scheme != trusted.scheme or parsed.netloc != trusted.netloc:
        return None
    segments = parsed.path.split("/")
    if len(segments) != 6:
        return None
    if segments[0] != "" or segments[1] != "admin" or segments[2] != "realms":
        return None
    if segments[3] != realm or segments[4] != "users":
        return None
    candidate = segments[5]
    if not candidate or candidate in (".", ".."):
        return None
    if any(character in candidate for character in ("/", "\\", ";")):
        return None
    if _has_control_characters(candidate):
        return None
    return candidate


def _sleep(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)
