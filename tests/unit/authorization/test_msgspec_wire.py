"""PR 8F msgspec semantic wire tests (domain -> positional MessagePack).

The experimental wire layer lives under ``benchmarks/`` and is
benchmark-only: these tests pin its contract without touching the
production domain model or the production evaluators.

- WIRE-SCHEMA: the v1 positional (``array_like=True``) schema encodes
  ``[version, action, permission_sets]`` with semantic components and
  NEVER a complete MTMF Action/Permission URN text.
- CONVERSION: ``build_payload`` extracts the already-parsed semantic
  components from the domain value objects (no URN reparsing), keeps
  the explicit wildcard flag, and preserves ALLOW/DENY effects.
- OWNERSHIP: Role/PermissionSet ownership corruption fails closed with
  the same :class:`PermissionEvaluationError` the production evaluators
  raise, before any serialization.
- VERSION: the payload always carries ``WIRE_VERSION == 1``.

No native module is required for these tests; the module is skipped
when the optional ``msgspec`` dev dependency is absent.
"""

from __future__ import annotations

import msgspec.msgpack as msgpack
import pytest
from authz_helpers import (  # type: ignore[import-untyped]
    corrupt_role,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)
from helpers import make_id, make_permission  # type: ignore[import-untyped]

from mtmf_core import PermissionEffect, PermissionEvaluationError
from mtmf_core.authorization.permission_evaluator import PermissionEvaluator

pytest.importorskip("msgspec")

from msgspec_wire import (
    WIRE_VERSION,
    ActionWire,
    EvaluationPayload,
    action_to_wire,
    build_payload,
    permission_to_wire,
)


def _encode(obj: object) -> bytes:
    return msgpack.Encoder().encode(obj)


# --- Wire schema ------------------------------------------------------------


def test_payload_is_a_positional_array_like_struct() -> None:
    # array_like is explicit: encoding never emits field-name maps.
    payload = EvaluationPayload(
        WIRE_VERSION,
        ActionWire("system", "principal", "set", "active"),
        [],
    )
    encoded = _encode(payload)
    assert isinstance(encoded, bytes)
    # The first byte must be a 3-element array header (0x93), proving
    # positional encoding rather than a map (0x83).
    assert encoded[0] == 0x93
    decoder = msgpack.Decoder(EvaluationPayload)
    assert decoder.decode(encoded) == payload


def test_wire_version_is_exactly_one() -> None:
    assert WIRE_VERSION == 1


def test_encoded_action_contains_no_full_urn_text() -> None:
    # The payload must carry semantic components only: the complete
    # canonical Action/Permission URN must never appear as a byte string.
    role_urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=role_urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=role_urn,
                rules=(("set", "*"), ("get", "object")),
            ),
        ),
    )
    action = make_action(resource="principal", verb="set", qualifier="active")
    encoded = _encode(build_payload(action, (role,)))
    assert b"urn:mtmf:iam:" not in encoded
    assert b"actions" not in encoded
    assert b"permissions" not in encoded


def test_encoded_wire_fields_are_semantic_components() -> None:
    wire = build_payload(
        make_action(resource="principal", verb="set", qualifier="active"),
        (),
    )
    assert wire.version == WIRE_VERSION
    assert wire.action == ActionWire("system", "principal", "set", "active")


# --- Domain conversion ------------------------------------------------------


def test_action_to_wire_reuses_already_parsed_components() -> None:
    action = make_action(resource="tenant", verb="transfer", qualifier="stewardship")
    wire = action_to_wire(action)
    assert wire == ActionWire(
        "system",
        action.urn.resource,
        action.urn.verb,
        action.urn.qualifier,
    )


def test_permission_to_wire_exact_and_wildcard_are_distinct() -> None:
    set_id = make_id()
    exact = make_permission(permission_set_id=set_id, verb="set", qualifier="active")
    wildcard = make_permission(permission_set_id=set_id, verb="set", qualifier="*")
    exact_wire = permission_to_wire(exact)
    wildcard_wire = permission_to_wire(wildcard)
    assert exact_wire.qualifier == "active"
    assert exact_wire.qualifier_wildcard is False
    assert wildcard_wire.qualifier == "*"
    assert wildcard_wire.qualifier_wildcard is True


def test_build_payload_flattens_roles_and_preserves_effects() -> None:
    role_urn = make_role_urn()
    allow = make_permission_set_with_rules(
        role_urn=role_urn, effect=PermissionEffect.ALLOW, rules=(("set", "active"),)
    )
    deny = make_permission_set_with_rules(
        role_urn=role_urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
    )
    role = make_role_from_sets(role_urn=role_urn, permission_sets=(allow, deny))
    payload = build_payload(
        make_action(resource="principal", verb="set", qualifier="active"),
        (role,),
    )
    assert [wire_set.effect for wire_set in payload.permission_sets] == ["allow", "deny"]
    assert len(payload.permission_sets[0].permissions) == 1
    assert len(payload.permission_sets[1].permissions) == 1
    assert payload.permission_sets[0].permissions[0].qualifier_wildcard is False
    assert payload.permission_sets[1].permissions[0].qualifier_wildcard is True


def test_build_payload_with_no_roles_is_an_empty_set_list() -> None:
    payload = build_payload(make_action(resource="principal", verb="set", qualifier="active"), ())
    assert payload.permission_sets == []


def test_build_payload_round_trips_through_the_decoder() -> None:
    role_urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=role_urn,
        permission_sets=(make_permission_set_with_rules(role_urn=role_urn, rules=(("set", "*"),)),),
    )
    action = make_action(resource="principal", verb="set", qualifier="active")
    payload = build_payload(action, (role,))
    decoder = msgpack.Decoder(EvaluationPayload)
    assert decoder.decode(_encode(payload)) == payload


# --- Ownership validation ---------------------------------------------------


def test_ownership_corruption_fails_closed_during_conversion() -> None:
    foreign_urn = make_role_urn(role_name="thief")
    own_urn = make_role_urn(role_name="owner")
    stolen_set = make_permission_set_with_rules(role_urn=foreign_urn)
    corrupted = corrupt_role(own_urn, (stolen_set,))
    action = make_action(resource="principal", verb="set", qualifier="active")
    with pytest.raises(PermissionEvaluationError):
        build_payload(action, (corrupted,))


def test_ownership_corruption_matches_production_evaluator_behavior() -> None:
    # The conversion layer must fail closed with the SAME narrow error
    # the production evaluators raise, before any serialization.
    foreign_urn = make_role_urn(role_name="thief")
    own_urn = make_role_urn(role_name="owner")
    stolen_set = make_permission_set_with_rules(role_urn=foreign_urn)
    corrupted = corrupt_role(own_urn, (stolen_set,))
    action = make_action(resource="principal", verb="set", qualifier="active")
    with pytest.raises(PermissionEvaluationError):
        build_payload(action, (corrupted,))
    with pytest.raises(PermissionEvaluationError):
        PermissionEvaluator().evaluate(action, (corrupted,))
