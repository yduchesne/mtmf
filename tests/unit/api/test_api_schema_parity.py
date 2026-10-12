"""JSON Schema / parser parity tests (plan matrix A26).

The checked-in schema and the runtime codecs must agree on every
schema-expressible constraint. Cross-field constraints (correlation,
``request_id`` uniqueness, time ordering, effect/reason coupling) are
documented as programmatic and are only asserted on the parser side.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from schema_validator import is_valid

from mtmf_api import (
    ApiContractValidationError,
    parse_error_json,
    parse_request_json,
    parse_response_json,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = REPO_ROOT / "packages" / "mtmf-api" / "schema" / "authorization-v1.schema.json"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

# Invalid fixtures whose rejection is expressible in JSON Schema. The
# remaining invalid fixtures encode cross-field rules the schema cannot
# express (effect/reason coupling, unique request_id, TTL ordering).
SCHEMA_EXPRESSIBLE_INVALID = {
    "invalid_duplicate_key.json",
    "invalid_unknown_field.json",
    "invalid_wildcard_action.json",
    "invalid_nil_uuid.json",
    "invalid_uppercase_uuid.json",
    "invalid_empty_actions.json",
    "invalid_resource_extra_field.json",
    "invalid_application_owned_missing_type.json",
    "invalid_bad_timestamp.json",
    "invalid_error_code.json",
    "invalid_error_secret_field.json",
}


def _schema() -> dict:
    with SCHEMA_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _parser_for(name: str):
    if name.startswith("request_"):
        return parse_request_json
    if name.startswith("response_"):
        return parse_response_json
    if name.startswith("error_"):
        return parse_error_json
    raise AssertionError(f"unexpected fixture name: {name}")


def _fixture_names() -> list[str]:
    return sorted(path.name for path in FIXTURE_DIR.glob("*.json"))


def test_schema_file_exists_and_is_strict() -> None:
    schema = _schema()
    request = schema["$defs"]["AuthorizationBatchRequest"]
    assert request["additionalProperties"] is False
    assert set(request["required"]) == {"tenant_id", "actions"}
    assert schema["$defs"]["ResourceTarget"]["oneOf"]


@pytest.mark.parametrize("name", [n for n in _fixture_names() if not n.startswith("invalid_")])
def test_a26_valid_fixtures_validate_against_schema_and_parser(name: str) -> None:
    schema = _schema()
    text = (FIXTURE_DIR / name).read_text(encoding="utf-8")
    instance = json.loads(text)
    assert is_valid(instance, schema), f"{name} must satisfy the JSON Schema"
    _parser_for(name)(text)


@pytest.mark.parametrize("name", [n for n in _fixture_names() if n.startswith("invalid_")])
def test_a26_invalid_fixtures_are_rejected_by_every_parser(name: str) -> None:
    text = (FIXTURE_DIR / name).read_text(encoding="utf-8")
    for parser in (parse_request_json, parse_response_json, parse_error_json):
        with pytest.raises(ApiContractValidationError):
            parser(text)


@pytest.mark.parametrize("name", sorted(SCHEMA_EXPRESSIBLE_INVALID))
def test_a26_schema_expressible_invalid_fixtures_fail_the_schema(name: str) -> None:
    schema = _schema()
    instance = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    assert not is_valid(instance, schema), f"{name} must fail the JSON Schema"


def test_a26_cross_field_fixtures_remain_parser_only() -> None:
    # These are valid per the structural schema but rejected by the DTOs.
    schema = _schema()
    cases = {
        "invalid_duplicate_request_id.json": parse_request_json,
        "invalid_allow_reason.json": parse_response_json,
        "invalid_deny_permitted.json": parse_response_json,
        "invalid_overlong_ttl.json": parse_response_json,
    }
    for name, parser in cases.items():
        text = (FIXTURE_DIR / name).read_text(encoding="utf-8")
        assert is_valid(json.loads(text), schema), f"{name} is expected to be schema-valid"
        with pytest.raises(ApiContractValidationError):
            parser(text)
