"""PR 17-C approved development authority tests.

The canonical development authority ``keycloak.mtmf.test`` is an explicit,
narrow extension of the historical loopback-only development trust set. These
tests pin that any other host remains rejected so the exact allowed set has one
definition and every call site stays fail-closed.
"""

from __future__ import annotations

from mtmf_service.authentication.development_authority import (
    APPROVED_DEVELOPMENT_HOSTS,
    CANONICAL_DEVELOPMENT_HOST,
    approved_development_host,
    is_approved_development_authority,
)


def test_canonical_host_is_approved():
    assert CANONICAL_DEVELOPMENT_HOST in APPROVED_DEVELOPMENT_HOSTS
    assert is_approved_development_authority("https://keycloak.mtmf.test:28443/realms/x")


def test_loopback_hosts_remain_approved():
    assert is_approved_development_authority("https://127.0.0.1:28443/realms/x")
    assert is_approved_development_authority("https://localhost:28443/realms/x")
    assert is_approved_development_authority("https://[::1]:28443/realms/x")


def test_arbitrary_non_loopback_host_is_rejected():
    assert not is_approved_development_authority("https://idp.example.com/realms/x")
    assert approved_development_host("https://idp.example.com/realms/x") is None


def test_subdomain_lookalikes_are_rejected():
    assert not is_approved_development_authority("https://evil.keycloak.mtmf.test/realms/x")
    assert not is_approved_development_authority("https://keycloak.mtmf.test.evil.example/")


def test_require_https_rejects_plain_http():
    assert is_approved_development_authority("http://keycloak.mtmf.test:28443")
    assert not is_approved_development_authority(
        "http://keycloak.mtmf.test:28443", require_https=True
    )


def test_missing_or_malformed_host_is_rejected():
    assert not is_approved_development_authority("")
    assert not is_approved_development_authority("not a url")
