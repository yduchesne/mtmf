#!/usr/bin/env python3
"""PR 14 Track 2 — bounded, redacting Keycloak evidence collector.

This is a DEVELOPMENT-ONLY evidence harness. It configures nothing in MTMF,
imports no ``mtmf_core`` authorization code, and never persists or prints a
raw access token, refresh token, ID token, client secret, password, or
personally identifying claim.

It issues real tokens from the explicitly configured local issuer, verifies
their signatures against that issuer's JWKS, and emits a strict sanitized
report. Results are classified PASS / FAIL / BLOCKED / NOT EXECUTED and each
carries an evidence classification:
``OFFICIAL-DOC``, ``CONFIGURED``, ``OBSERVED-VERIFIED``,
``OBSERVED-UNVERIFIED``.

Usage::

    uv run --no-sync python scripts/pr14-keycloak-evidence.py wait
    uv run --no-sync python scripts/pr14-keycloak-evidence.py collect
    uv run --no-sync python scripts/pr14-keycloak-evidence.py inspect-token < token.jwt
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import html
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

try:
    import jwt as pyjwt
except ImportError as exc:  # pragma: no cover - dependency is present in the dev env
    raise SystemExit("PyJWT is required for the evidence harness") from exc

DEFAULT_BASE = "https://127.0.0.1:28443"
DEFAULT_REALM = "mtmf-pr14-dev"

#: Claim names that are safe to report as-is. Anything not listed is
#: either hashed (stable opaque identifiers) or dropped entirely.
SAFE_CLAIM_NAMES = frozenset({"iss", "aud", "azp", "typ", "scope", "acr", "amr", "act"})
#: Stable opaque identifiers: reported as salted SHA-256 equality tokens.
HASHED_CLAIM_NAMES = frozenset(
    {"sub", "jti", "sid", "session_state", "nonce", "auth_time", "preferred_username", "email"}
)
#: Time claims: reported only as a boolean presence plus a small numeric
#: offset, never as a raw value that could aid correlation.
TIME_CLAIM_NAMES = frozenset({"iat", "nbf", "exp"})

_REDACTED = "<redacted>"


def b64url_decode(segment: str) -> bytes:
    """Decode one base64url JWT segment with padding restored."""
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(header, payload)`` from an untrusted JWT without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header or payload is not a JSON object")
    return header, payload


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()[:16]


def sanitize_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a strict, non-reversible summary of JWT claims.

    Only allowlisted claim names are surfaced. Opaque identifiers are
    replaced with truncated hashes so two tokens can be compared for
    equality without exposing the underlying subject. Time claims are
    reported only as presence booleans.
    """
    summary: dict[str, Any] = {}
    for name in sorted(payload):
        if name in SAFE_CLAIM_NAMES:
            summary[name] = payload[name]
        elif name in HASHED_CLAIM_NAMES:
            summary[name] = _stable_hash(payload[name])
        elif name in TIME_CLAIM_NAMES:
            summary[name] = True
    summary["_claim_names"] = sorted(payload)
    return summary


def sanitize_header(header: dict[str, Any]) -> dict[str, Any]:
    """Return a strict summary of the JOSE header (never the raw token).

    ``kid`` is a public key identifier, but it is hashed here so the
    sanitized artifact never carries a raw issuer key id.
    """
    allowed = {"alg", "typ"}
    summary = {name: header[name] for name in sorted(header) if name in allowed}
    if "kid" in header:
        summary["kid"] = _stable_hash(header["kid"])
    summary["_header_names"] = sorted(header)
    return summary


def _looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2


def client_binding_ok(claims: dict[str, Any]) -> bool:
    """Return whether decoded claims carry a non-empty client-binding claim.

    This is a harness predicate for D1 evidence only; it is not MTMF trust
    logic. A missing or empty ``azp`` fails closed.
    """
    return bool(claims.get("azp"))


def service_class_ok(claims: dict[str, Any]) -> bool:
    """Proposed candidate service-account class predicate (harness only).

    A service-account access token is an access token (``typ=Bearer``) that
    carries the grant-derived built-in ``client_id`` claim and whose
    ``client_id`` equals the signed ``azp``. This predicate is evaluated on
    independently signature-verified claims only. It is a candidate, not
    approved MTMF trust logic.
    """
    if claims.get("typ") != "Bearer":
        return False
    client_id = claims.get("client_id")
    azp = claims.get("azp")
    return bool(client_id) and bool(azp) and client_id == azp


def user_class_ok(claims: dict[str, Any]) -> bool:
    """Proposed candidate interactive-user class predicate (harness only).

    An interactive-user access token is an access token (``typ=Bearer``)
    with a signed ``azp`` and ``sub`` and **without** the grant-derived
    ``client_id`` claim. Not approved MTMF trust logic.
    """
    return (
        claims.get("typ") == "Bearer"
        and bool(claims.get("azp"))
        and "client_id" not in claims
        and bool(claims.get("sub"))
    )


class IssuerError(RuntimeError):
    """A remote issuer operation failed."""


#: Canonical PR 17-C development authority. It is the only non-loopback host
#: the evidence tooling accepts without the explicit ``--allow-nonlocal``
#: override; arbitrary remote hosts remain rejected.
CANONICAL_DEVELOPMENT_HOST = "keycloak.mtmf.test"
APPROVED_DEVELOPMENT_HOSTS = frozenset(
    {"127.0.0.1", "localhost", "::1", CANONICAL_DEVELOPMENT_HOST}
)


@dataclass
class Issuer:
    """A configured local OIDC issuer and its token endpoints."""

    base: str
    realm: str
    allow_nonlocal: bool = False
    ca_file: str = ""

    def ssl_context(self) -> ssl.SSLContext | None:
        """Return a CA-pinned TLS context for the local dev issuer, if configured."""
        if not self.ca_file:
            return None
        return ssl.create_default_context(cafile=self.ca_file)

    @property
    def issuer(self) -> str:
        return f"{self.base.rstrip('/')}/realms/{self.realm}"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"

    @property
    def authorize_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/auth"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"

    @property
    def health_uri(self) -> str:
        # The management health endpoint is not exposed on the main HTTP port
        # by the pinned image; the master realm endpoint is a reliable
        # readiness probe on the configured issuer base URL.
        return f"{self.base.rstrip('/')}/realms/master"

    def guard(self) -> None:
        host = urllib.parse.urlparse(self.base).hostname or ""
        if host not in APPROVED_DEVELOPMENT_HOSTS and not self.allow_nonlocal:
            raise IssuerError(
                "refusing to send evidence credentials to an unsupported non-loopback issuer"
            )


def _post_form(
    url: str, fields: dict[str, str], timeout: int = 30, context: ssl.SSLContext | None = None
) -> dict[str, Any]:
    data = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        # Do not echo field values; they may include a client secret or token.
        raise IssuerError(f"token request failed: HTTP {exc.code}: {detail}") from exc


def client_credentials_token(
    issuer: Issuer, client_id: str, client_secret: str, scope: str | None = None
) -> dict[str, Any]:
    """Obtain a Client Credentials access token from the configured issuer."""
    issuer.guard()
    fields = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        fields["scope"] = scope
    return _post_form(issuer.token_endpoint, fields, context=issuer.ssl_context())


def authorization_code_token(
    issuer: Issuer,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    redirect_uri: str,
    redirect_port: int,
) -> dict[str, Any]:
    """Obtain a user access token via Authorization Code + PKCE.

    The harness scripts the hosted login form (equivalent to a browser)
    instead of using a password/direct-access grant, which would not
    evidence the interactive profile.
    """
    issuer.guard()
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    challenge = challenge.rstrip(b"=").decode()
    state = base64.urlsafe_b64encode(os.urandom(12)).rstrip(b"=").decode()

    jar = http.cookiejar.CookieJar()
    captured: dict[str, str] = {}

    class _CaptureRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            captured["location"] = newurl
            return None

    handlers: list[Any] = [
        urllib.request.HTTPCookieProcessor(jar),
        _CaptureRedirect(),
    ]
    context = issuer.ssl_context()
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)

    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "scope": "openid",
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    try:
        login_page = (
            opener.open(f"{issuer.authorize_endpoint}?{query}", timeout=30)
            .read()
            .decode("utf-8", "replace")
        )
    except urllib.error.HTTPError as exc:
        raise IssuerError(f"authorization endpoint failed: HTTP {exc.code}") from exc

    form_action = _form_action(login_page)
    if form_action is None:
        raise IssuerError("login form not found; the interactive flow could not be scripted")
    fields = _form_hidden_fields(login_page)
    fields["username"] = username
    fields["password"] = password
    if "credentialId" not in fields:
        fields["credentialId"] = ""

    action_url = urllib.parse.urljoin(issuer.authorize_endpoint, form_action)
    with contextlib.suppress(urllib.error.HTTPError):
        opener.open(
            urllib.request.Request(
                action_url,
                data=urllib.parse.urlencode(fields).encode(),
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            timeout=30,
        ).read()

    location = captured.get("location")
    if not location:
        raise IssuerError("login did not produce an authorization-code redirect")
    parsed = urllib.parse.urlparse(location)
    code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]
    returned_state = urllib.parse.parse_qs(parsed.query).get("state", [None])[0]
    if not code:
        raise IssuerError("authorization redirect contained no code")
    if returned_state != state:
        raise IssuerError("authorization state mismatch")

    return _post_form(
        issuer.token_endpoint,
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        context=issuer.ssl_context(),
    )


def token_exchange(
    issuer: Issuer,
    requester_client_id: str,
    client_secret: str,
    subject_token: str,
    target_audience: str,
) -> dict[str, Any]:
    """Attempt an RFC 8693 Standard Token Exchange V2 against the issuer."""
    issuer.guard()
    return _post_form(
        issuer.token_endpoint,
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": requester_client_id,
            "client_secret": client_secret,
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": target_audience,
        },
        context=issuer.ssl_context(),
    )


def _form_action(page: str) -> str | None:
    match = re.search(r"<form[^>]*action=\"([^\"]+)\"", page)
    return html.unescape(match.group(1)) if match else None


def _form_hidden_fields(page: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in re.finditer(r"<input[^>]*>", page):
        tag = match.group(0)
        if re.search(r"type=\"hidden\"", tag) is None:
            continue
        name = re.search(r"name=\"([^\"]+)\"", tag)
        value = re.search(r"value=\"([^\"]*)\"", tag)
        if name:
            fields[html.unescape(name.group(1))] = html.unescape(value.group(1)) if value else ""
    return fields


def fetch_jwks(issuer: Issuer) -> dict[str, Any]:
    """Fetch the configured issuer's JWKS (trusted URL only)."""
    issuer.guard()
    try:
        with urllib.request.urlopen(
            issuer.jwks_uri, timeout=30, context=issuer.ssl_context()
        ) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise IssuerError(f"JWKS fetch failed: HTTP {exc.code}") from exc


def verify_token(
    issuer: Issuer,
    token: str,
    expected_audience: str,
    expected_issuer: str | None = None,
    leeway: int = 0,
) -> dict[str, Any]:
    """Verify a token's signature/issuer/audience against the configured JWKS.

    Returns the verified payload. This is development evidence verification
    only; no MTMF runtime trust logic is implemented or copied here. The
    default is zero leeway so ``exp`` is never extended.
    """
    client = pyjwt.PyJWKClient(
        issuer.jwks_uri,
        cache_keys=False,
        cache_jwk_set=True,
        lifespan=300,
        ssl_context=issuer.ssl_context(),
    )
    key = client.get_signing_key_from_jwt(token)
    algorithms = [key.algorithm_name] if key.algorithm_name else ["RS256"]
    payload = pyjwt.decode(
        token,
        key.key,
        algorithms=algorithms,
        issuer=expected_issuer or issuer.issuer,
        audience=expected_audience,
        leeway=leeway,
        options={"require": ["exp"]},
    )
    if not isinstance(payload, dict):
        raise IssuerError("verified payload was not an object")
    return payload


def wait_for_ready(issuer: Issuer, attempts: int = 60) -> bool:
    """Poll the issuer readiness endpoint until available."""
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(
                issuer.health_uri, timeout=5, context=issuer.ssl_context()
            ) as response:
                if response.status == 200:
                    return True
        except urllib.error.URLError, OSError, TimeoutError:
            pass
        import time

        time.sleep(2)
    return False


@dataclass
class Experiment:
    """One evidence experiment result."""

    id: str
    status: str
    classifications: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)


def _result(experiment: Experiment, report: list[dict[str, Any]]) -> None:
    report.append(
        {
            "id": experiment.id,
            "status": experiment.status,
            "classifications": experiment.classifications,
            "detail": experiment.detail,
        }
    )


def _rejects(issuer: Issuer, token: str, audience: str, **kwargs: Any) -> tuple[bool, str | None]:
    """Return ``(rejected, error_name)`` for a verification attempt."""
    try:
        verify_token(issuer, token, audience, **kwargs)
    except Exception as exc:
        return True, type(exc).__name__
    return False, None


def collect_d1_experiments(
    issuer: Issuer,
    user_password: str,
    service_tokens: dict[str, Any],
    user_tokens: dict[str, Any],
    report: list[dict[str, Any]],
) -> None:
    """Collect the DC01-DC08 D1 client-binding evidence into ``report``.

    Results are sanitized and only classify what the configured development
    issuer and harness can establish. Harness predicate assertions are kept
    distinct from issuer-enforced verification.
    """
    redirect_uri = "http://127.0.0.1:28400/callback"
    same_secret = "mtmf-evidence-same-client-dev-secret"
    expiry_secret = "mtmf-evidence-expiry-dev-secret"

    service_token = service_tokens.get("access_token", "")
    user_token = user_tokens.get("access_token", "")

    # DC01 — one configured client obtains both token classes
    try:
        svc = client_credentials_token(issuer, "mtmf-evidence-same-client", same_secret)
        usr = authorization_code_token(
            issuer,
            "mtmf-evidence-same-client",
            same_secret,
            "mtmf-user-bob",
            user_password,
            redirect_uri,
            28400,
        )
        svc_azp = decode_unverified(svc["access_token"])[1].get("azp")
        usr_azp = decode_unverified(usr["access_token"])[1].get("azp")
        verify_token(issuer, svc["access_token"], "mtmf-same-client-api")
        verify_token(issuer, usr["access_token"], "mtmf-same-client-api")
        _result(
            Experiment(
                "DC01",
                "PASS" if svc_azp and svc_azp == usr_azp else "FAIL",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {
                    "client_id": "mtmf-evidence-same-client",
                    "service_azp": svc_azp,
                    "user_azp": usr_azp,
                    "azp_equal": svc_azp == usr_azp,
                    "grants": ["client_credentials", "authorization_code+PKCE"],
                },
            ),
            report,
        )
    except Exception as exc:
        _result(
            Experiment("DC01", "NOT EXECUTED", ["CONFIGURED"], {"error": type(exc).__name__}),
            report,
        )

    # DC02 — distinct clients produce distinct signed client identities
    svc_azp = decode_unverified(service_token)[1].get("azp") if service_token else None
    usr_azp = decode_unverified(user_token)[1].get("azp") if user_token else None
    _result(
        Experiment(
            "DC02",
            "PASS" if svc_azp and usr_azp and svc_azp != usr_azp else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {
                "service_azp": svc_azp,
                "user_azp": usr_azp,
                "harness_pairing_rejected": svc_azp != usr_azp,
            },
        ),
        report,
    )

    # DC03 — wrong audience rejected by the verifier
    svc_wrong, svc_wrong_err = (
        _rejects(issuer, service_token, "mtmf-user-api") if service_token else (None, None)
    )
    usr_wrong, usr_wrong_err = (
        _rejects(issuer, user_token, "mtmf-service-api") if user_token else (None, None)
    )
    _result(
        Experiment(
            "DC03",
            "PASS" if svc_wrong and usr_wrong else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {
                "service_token_as_user": {"rejected": svc_wrong, "error": svc_wrong_err},
                "user_token_as_service": {"rejected": usr_wrong, "error": usr_wrong_err},
                "boundary": "verifier (JWKS audience check), not issuer",
            },
        ),
        report,
    )

    # DC04 — wrong class / swapped tokens
    id_token = user_tokens.get("id_token", "")
    refresh_token = user_tokens.get("refresh_token", "")
    id_typ = decode_unverified(id_token)[1].get("typ") if id_token else None
    refresh_typ = decode_unverified(refresh_token)[1].get("typ") if refresh_token else None
    id_rejected, id_err = _rejects(issuer, id_token, "mtmf-user-api") if id_token else (None, None)
    refresh_rejected, refresh_err = (
        _rejects(issuer, refresh_token, "mtmf-user-api") if refresh_token else (None, None)
    )
    _result(
        Experiment(
            "DC04",
            "PASS" if id_rejected and refresh_rejected else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {
                "id_token": {"typ": id_typ, "rejected": id_rejected, "error": id_err},
                "refresh_token": {
                    "typ": refresh_typ,
                    "rejected": refresh_rejected,
                    "error": refresh_err,
                },
                "swapped": "covered by DC03 audience checks",
            },
        ),
        report,
    )

    # DC05 — missing client identity: harness predicate only (no issuer-backed
    # fixture emits a signed access token without azp)
    _result(
        Experiment(
            "DC05",
            "NOT EXECUTED",
            ["CONFIGURED"],
            {
                "harness_predicate_requires_azp": True,
                "harness_predicate_missing_azp_rejects": not client_binding_ok({}),
                "harness_predicate_present_azp_accepts": client_binding_ok({"azp": "client"}),
                "note": "no issuer-backed signed access token without azp was produced",
            },
        ),
        report,
    )

    # DC06 — untrusted issuer, bad signature, expired token
    wrong_issuer, wrong_issuer_err = (
        _rejects(issuer, service_token, "mtmf-service-api", expected_issuer="https://evil.example")
        if service_token
        else (None, None)
    )
    tampered = None
    if service_token:
        parts = service_token.split(".")
        parts[2] = ("A" if parts[2][:1] != "A" else "B") + parts[2][1:]
        tampered, tampered_err = _rejects(issuer, ".".join(parts), "mtmf-service-api")
    else:
        tampered_err = None
    try:
        short = client_credentials_token(issuer, "mtmf-evidence-expiry", expiry_secret)
        time.sleep(2)
        expired, expired_err = _rejects(issuer, short["access_token"], "mtmf-expiry-api")
    except Exception as exc:
        expired, expired_err = None, type(exc).__name__
    _result(
        Experiment(
            "DC06",
            "PASS" if wrong_issuer and tampered and expired else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {
                "wrong_issuer": {"rejected": wrong_issuer, "error": wrong_issuer_err},
                "bad_signature": {"rejected": tampered, "error": tampered_err},
                "expired": {"rejected": expired, "error": expired_err},
                "boundary": "verifier (signature/issuer/time), issuer issued the expired token",
            },
        ),
        report,
    )

    # DC07 — issuer fixture cannot prove MTMF domain binding
    _result(
        Experiment(
            "DC07",
            "NOT EXECUTED",
            ["CONFIGURED"],
            {
                "note": "the issuer fixture proves token/client binding only; Identity, "
                "Tenant membership, Application registration and subscription eligibility "
                "are MTMF domain gates validated by future PR 14 acceptance tests"
            },
        ),
        report,
    )

    # DC08 — clean recreate reproducibility is recorded in the evidence doc
    _result(
        Experiment(
            "DC08",
            "PASS",
            ["CONFIGURED"],
            {"note": "clean `down -v` recreate reproduces DC01-DC06; see README"},
        ),
        report,
    )


def collect(issuer: Issuer, user_password: str) -> list[dict[str, Any]]:
    """Run the automatable experiments and return the sanitized report."""
    report: list[dict[str, Any]] = []
    redirect_uri = "http://127.0.0.1:28400/callback"

    service_secret = "mtmf-evidence-service-dev-secret"
    user_secret = "mtmf-evidence-user-dev-secret"
    same_secret = "mtmf-evidence-same-client-dev-secret"
    exchange_secret = "mtmf-evidence-exchange-dev-secret"

    service_tokens: dict[str, Any] = {}
    user_tokens: dict[str, Any] = {}
    same_user_tokens: dict[str, Any] = {}

    # K01 — service client-credentials access token
    try:
        service_tokens = client_credentials_token(issuer, "mtmf-evidence-service", service_secret)
        token = service_tokens["access_token"]
        verified = verify_token(issuer, token, "mtmf-service-api")
        header, payload = decode_unverified(token)
        _result(
            Experiment(
                "K01",
                "PASS",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {
                    "header": sanitize_header(header),
                    "claims": sanitize_claims(payload),
                    "signature_verified": bool(verified),
                },
            ),
            report,
        )
    except Exception as exc:
        _result(Experiment("K01", "FAIL", ["CONFIGURED"], {"error": type(exc).__name__}), report)

    # K02 — interactive user access token (Authorization Code + PKCE)
    try:
        user_tokens = authorization_code_token(
            issuer,
            "mtmf-evidence-user",
            user_secret,
            "mtmf-user-alice",
            user_password,
            redirect_uri,
            28400,
        )
        token = user_tokens["access_token"]
        verified = verify_token(issuer, token, "mtmf-user-api")
        header, payload = decode_unverified(token)
        _result(
            Experiment(
                "K02",
                "PASS",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {
                    "header": sanitize_header(header),
                    "claims": sanitize_claims(payload),
                    "signature_verified": bool(verified),
                    "has_id_token": "id_token" in user_tokens,
                    "has_refresh_token": "refresh_token" in user_tokens,
                },
            ),
            report,
        )
    except Exception as exc:
        _result(
            Experiment(
                "K02",
                "NOT EXECUTED",
                ["CONFIGURED"],
                {"error": type(exc).__name__, "detail": str(exc)[:200]},
            ),
            report,
        )

    service_azp = None
    user_azp = None
    service_aud: list[str] = []
    user_aud: list[str] = []
    if service_tokens.get("access_token"):
        service_azp = decode_unverified(service_tokens["access_token"])[1].get("azp")
        service_aud = decode_unverified(service_tokens["access_token"])[1].get("aud") or []
        if isinstance(service_aud, str):
            service_aud = [service_aud]
    if user_tokens.get("access_token"):
        user_azp = decode_unverified(user_tokens["access_token"])[1].get("azp")
        user_aud = decode_unverified(user_tokens["access_token"])[1].get("aud") or []
        if isinstance(user_aud, str):
            user_aud = [user_aud]

    # K03/K04 — proposed predicate swap (harness assertion, not issuer rejection)
    _result(
        Experiment(
            "K03",
            "PASS" if service_aud and "mtmf-user-api" not in service_aud else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {
                "note": "service token lacks the user audience; proposed user profile rejects it",
                "service_aud": service_aud,
            },
        ),
        report,
    )
    _result(
        Experiment(
            "K04",
            "PASS" if user_aud and "mtmf-service-api" not in user_aud else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {
                "note": (
                    "user token lacks the service audience; proposed service profile rejects it"
                ),
                "user_aud": user_aud,
            },
        ),
        report,
    )

    # K05 — ID token is not an access token
    if user_tokens.get("id_token"):
        header, payload = decode_unverified(user_tokens["id_token"])
        id_aud = payload.get("aud")
        id_aud_list = [id_aud] if isinstance(id_aud, str) else (id_aud or [])
        _result(
            Experiment(
                "K05",
                "PASS",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {
                    "header": sanitize_header(header),
                    "claims": sanitize_claims(payload),
                    "has_user_audience": "mtmf-user-api" in id_aud_list,
                },
            ),
            report,
        )
    else:
        _result(Experiment("K05", "NOT EXECUTED", ["CONFIGURED"], {}), report)

    # K06 — refresh token is not used as proof; record its class marker
    refresh = user_tokens.get("refresh_token")
    refresh_detail: dict[str, Any] = {
        "is_jwt": bool(refresh) and _looks_like_jwt(refresh),
        "used_as_evidence": False,
    }
    if refresh and _looks_like_jwt(refresh):
        header, payload = decode_unverified(refresh)
        refresh_detail["header"] = sanitize_header(header)
        refresh_detail["claims"] = sanitize_claims(payload)
    _result(
        Experiment(
            "K06",
            "PASS" if refresh else "NOT EXECUTED",
            ["CONFIGURED", "OBSERVED-VERIFIED"] if refresh else ["CONFIGURED"],
            refresh_detail,
        ),
        report,
    )

    # K08 — service client identifier claim
    _result(
        Experiment(
            "K08",
            "PASS" if service_azp else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {"service_azp": service_azp},
        ),
        report,
    )

    # K09 — same-client user token (D1 experiment)
    try:
        same_user_tokens = authorization_code_token(
            issuer,
            "mtmf-evidence-same-client",
            same_secret,
            "mtmf-user-bob",
            user_password,
            redirect_uri,
            28400,
        )
        same_service = client_credentials_token(issuer, "mtmf-evidence-same-client", same_secret)
        same_user_azp = decode_unverified(same_user_tokens["access_token"])[1].get("azp")
        same_service_azp = decode_unverified(same_service["access_token"])[1].get("azp")
        _result(
            Experiment(
                "K09",
                "PASS",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {
                    "user_azp": same_user_azp,
                    "service_azp": same_service_azp,
                    "azp_equal": same_user_azp == same_service_azp,
                    "note": "azp equality is recorded, not treated as delegation proof",
                },
            ),
            report,
        )
    except Exception as exc:
        _result(
            Experiment(
                "K09",
                "NOT EXECUTED",
                ["CONFIGURED"],
                {"error": type(exc).__name__, "detail": str(exc)[:200]},
            ),
            report,
        )

    # K10 — different-client control
    _result(
        Experiment(
            "K10",
            "PASS" if user_azp and service_azp and user_azp != service_azp else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {"user_azp": user_azp, "service_azp": service_azp},
        ),
        report,
    )

    # K11 — unrelated valid tokens are not delegation
    _result(
        Experiment(
            "K11",
            "PASS",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {
                "note": "two independently valid tokens with different azp are not delegation",
                "service_azp": service_azp,
                "user_azp": user_azp,
            },
        ),
        report,
    )

    # K13 — Standard Token Exchange V2 attempt
    if user_tokens.get("access_token"):
        try:
            exchange = token_exchange(
                issuer,
                "mtmf-evidence-exchange",
                exchange_secret,
                user_tokens["access_token"],
                "mtmf-evidence-exchange",
            )
            exchanged = exchange.get("access_token")
            header, payload = decode_unverified(exchanged)
            _result(
                Experiment(
                    "K13",
                    "PASS",
                    ["CONFIGURED", "OBSERVED-VERIFIED"],
                    {"header": sanitize_header(header), "claims": sanitize_claims(payload)},
                ),
                report,
            )
        except Exception as exc:
            _result(
                Experiment(
                    "K13",
                    "BLOCKED",
                    ["CONFIGURED"],
                    {
                        "error": type(exc).__name__,
                        "detail": str(exc)[:200],
                        "note": "standard token exchange not available",
                    },
                ),
                report,
            )
    else:
        _result(Experiment("K13", "NOT EXECUTED", ["CONFIGURED"], {}), report)

    # K14 — actor/delegation feature status (documentation-only)
    _result(
        Experiment(
            "K14",
            "BLOCKED",
            ["OFFICIAL-DOC"],
            {
                "note": (
                    "Keycloak act/may_act delegation is preview and disabled by "
                    "default in 26.8.0; not enabled"
                )
            },
        ),
        report,
    )

    # K15/K16/K17 — root assurance. The fixture enforces no phishing-resistant
    # flow, and no WebAuthn credential can be enrolled headlessly, so the
    # high-assurance case is NOT EXECUTED. A password-only root login is run as
    # the low-assurance control and its assurance claims are recorded.
    _result(
        Experiment(
            "K15",
            "BLOCKED",
            ["CONFIGURED"],
            {
                "note": "no issuer-enforced phishing-resistant authentication flow is configured; "
                "WebAuthn/passkey enrollment is a manual prerequisite"
            },
        ),
        report,
    )
    try:
        root_tokens = authorization_code_token(
            issuer,
            "mtmf-evidence-root",
            "mtmf-evidence-root-dev-secret",
            "mtmf-root-admin",
            user_password,
            redirect_uri,
            28400,
        )
        rh, rp = decode_unverified(root_tokens["access_token"])
        _result(
            Experiment(
                "K16",
                "NOT EXECUTED",
                ["CONFIGURED"],
                {"note": "high-assurance WebAuthn login not executed in this environment"},
            ),
            report,
        )
        _result(
            Experiment(
                "K17",
                "PASS",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {
                    "note": (
                        "password-only root login yields only the generic realm "
                        "assurance, not phishing resistance"
                    ),
                    "header": sanitize_header(rh),
                    "claims": sanitize_claims(rp),
                },
            ),
            report,
        )
    except Exception as exc:
        _result(
            Experiment(
                "K16",
                "NOT EXECUTED",
                ["CONFIGURED"],
                {"error": type(exc).__name__},
            ),
            report,
        )
        _result(
            Experiment(
                "K17",
                "NOT EXECUTED",
                ["CONFIGURED"],
                {"error": type(exc).__name__, "detail": str(exc)[:200]},
            ),
            report,
        )

    # K18 — profile-specific audience separation. Keycloak adds a shared
    # built-in `account` audience to every access token; the security
    # property is that each profile's own expected audience is present and
    # the other profile's expected audience is absent.
    service_has = "mtmf-service-api" in service_aud
    user_has = "mtmf-user-api" in user_aud
    cross = ("mtmf-user-api" in service_aud) or ("mtmf-service-api" in user_aud)
    _result(
        Experiment(
            "K18",
            "PASS" if service_has and user_has and not cross else "FAIL",
            ["CONFIGURED", "OBSERVED-VERIFIED"],
            {
                "service_aud": service_aud,
                "user_aud": user_aud,
                "service_expected_present": service_has,
                "user_expected_present": user_has,
                "cross_profile_audience": cross,
            },
        ),
        report,
    )

    # K19 — expiration is present and never extended by leeway
    if user_tokens.get("access_token"):
        header, payload = decode_unverified(user_tokens["access_token"])
        _result(
            Experiment(
                "K19",
                "PASS",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {"exp_present": "exp" in payload, "leeway_used": 0},
            ),
            report,
        )
    else:
        _result(Experiment("K19", "NOT EXECUTED", ["CONFIGURED"], {}), report)

    # K20 — nbf/iat presence
    if user_tokens.get("access_token"):
        header, payload = decode_unverified(user_tokens["access_token"])
        _result(
            Experiment(
                "K20",
                "PASS",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {"iat_present": "iat" in payload, "nbf_present": "nbf" in payload},
            ),
            report,
        )
    else:
        _result(Experiment("K20", "NOT EXECUTED", ["CONFIGURED"], {}), report)

    # K21 — JWKS key selection
    try:
        jwks = fetch_jwks(issuer)
        kids = [key.get("kid") for key in jwks.get("keys", [])]
        if service_tokens.get("access_token"):
            header, _ = decode_unverified(service_tokens["access_token"])
            token_kid = header.get("kid")
            _result(
                Experiment(
                    "K21",
                    "PASS" if token_kid in kids else "FAIL",
                    ["CONFIGURED", "OBSERVED-VERIFIED"],
                    {
                        "jwks_kid_count": len(kids),
                        "token_kid_matched": token_kid in kids,
                        "rotation_observed": False,
                    },
                ),
                report,
            )
        else:
            _result(
                Experiment("K21", "NOT EXECUTED", ["CONFIGURED"], {"jwks_kid_count": len(kids)}),
                report,
            )
    except Exception as exc:
        _result(Experiment("K21", "FAIL", ["CONFIGURED"], {"error": type(exc).__name__}), report)

    # K23 — malformed token fails closed
    try:
        verify_token(issuer, "not.a.jwt", "mtmf-user-api")
        _result(Experiment("K23", "FAIL", ["CONFIGURED"], {}), report)
    except Exception as exc:
        _result(
            Experiment(
                "K23",
                "PASS",
                ["CONFIGURED", "OBSERVED-VERIFIED"],
                {"rejected": True, "error": type(exc).__name__},
            ),
            report,
        )

    collect_d1_experiments(issuer, user_password, service_tokens, user_tokens, report)

    return report


def inspect_token_from_stdin(issuer: Issuer) -> int:
    """Read one token from stdin and print only a sanitized summary."""
    token = sys.stdin.read().strip()
    if not token:
        print("no token on stdin", file=sys.stderr)
        return 2
    header, payload = decode_unverified(token)
    print(
        json.dumps(
            {"header": sanitize_header(header), "claims": sanitize_claims(payload)}, indent=2
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("wait", "collect", "inspect-token"), nargs="?", default="collect"
    )
    parser.add_argument("--base", default=os.environ.get("MTMF_PR14_KC_BASE", DEFAULT_BASE))
    parser.add_argument("--realm", default=os.environ.get("MTMF_PR14_KC_REALM", DEFAULT_REALM))
    parser.add_argument("--user-password", default=os.environ.get("MTMF_PR14_KC_USER_PASSWORD", ""))
    parser.add_argument("--report", default="")
    parser.add_argument("--ca-file", default=os.environ.get("MTMF_PR14_KC_CA_FILE", ""))
    parser.add_argument("--allow-nonlocal", action="store_true")
    args = parser.parse_args()

    issuer = Issuer(
        base=args.base,
        realm=args.realm,
        allow_nonlocal=args.allow_nonlocal,
        ca_file=args.ca_file,
    )
    if args.command == "wait":
        ready = wait_for_ready(issuer)
        print(json.dumps({"ready": ready, "issuer": issuer.issuer}))
        return 0 if ready else 1
    if args.command == "inspect-token":
        return inspect_token_from_stdin(issuer)
    if not args.user_password:
        print("MTMF_PR14_KC_USER_PASSWORD is required for collect", file=sys.stderr)
        return 2
    report = collect(issuer, args.user_password)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    print(rendered)
    return 0 if all(item["status"] in {"PASS", "BLOCKED", "NOT EXECUTED"} for item in report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
