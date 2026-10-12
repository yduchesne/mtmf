"""A tiny JSON Schema subset validator used only by the parity tests.

The repository does not depend on a third-party JSON Schema library, so
this module implements just enough of draft 2020-12 to cross-check the
checked-in ``authorization-v1.schema.json`` against the runtime codecs:
local ``$ref``, ``oneOf``/``allOf``/``not``, ``const``/``enum``, ``type``,
``properties``/``required``/``additionalProperties``, ``pattern``,
``minLength``/``maxLength``, ``minItems``/``maxItems``, and ``items``.

It is test-only and is never imported by production code.
"""

from __future__ import annotations

import re
from typing import Any


class SchemaViolationError(AssertionError):
    """Raised when an instance does not validate against the schema."""


def _resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    reference = schema.get("$ref")
    if reference is None:
        return schema
    if not reference.startswith("#/"):
        raise SchemaViolationError(f"unsupported non-local $ref: {reference!r}")
    node: Any = root
    for part in reference[2:].split("/"):
        node = node[part]
    return node


def _type_ok(instance: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "null":
        return instance is None
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    raise SchemaViolationError(f"unsupported schema type: {expected!r}")


def _validate(instance: Any, schema: dict[str, Any], root: dict[str, Any]) -> None:
    schema = _resolve(schema, root)

    if "oneOf" in schema:
        matches = sum(1 for candidate in schema["oneOf"] if is_valid(instance, candidate, root))
        if matches != 1:
            raise SchemaViolationError(f"oneOf matched {matches} branches for {instance!r}")
    if "allOf" in schema:
        for candidate in schema["allOf"]:
            _validate(instance, candidate, root)
    if "not" in schema and is_valid(instance, schema["not"], root):
        raise SchemaViolationError(f"'not' branch matched for {instance!r}")
    if "const" in schema and instance != schema["const"]:
        raise SchemaViolationError(f"const mismatch: {instance!r} != {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaViolationError(f"value not in enum: {instance!r}")

    expected_type = schema.get("type")
    if expected_type is not None and not _type_ok(instance, expected_type):
        raise SchemaViolationError(f"type mismatch: {instance!r} is not {expected_type}")

    if isinstance(instance, str):
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            raise SchemaViolationError(f"pattern mismatch: {instance!r}")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise SchemaViolationError(f"string shorter than minLength: {instance!r}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise SchemaViolationError(f"string longer than maxLength: {instance!r}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            raise SchemaViolationError("array shorter than minItems")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            raise SchemaViolationError("array longer than maxItems")
        if "items" in schema:
            for item in instance:
                _validate(item, schema["items"], root)

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for key, subschema in properties.items():
            if key in instance:
                _validate(instance[key], subschema, root)
        if schema.get("additionalProperties") is False:
            extra = set(instance) - set(properties)
            if extra:
                raise SchemaViolationError(
                    f"additional properties are not allowed: {sorted(extra)!r}"
                )
        for key in schema.get("required", []):
            if key not in instance:
                raise SchemaViolationError(f"missing required property: {key!r}")


def is_valid(instance: Any, schema: dict[str, Any], root: dict[str, Any] | None = None) -> bool:
    """Return whether ``instance`` validates against ``schema``."""
    resolved_root = schema if root is None else root
    try:
        _validate(instance, schema, resolved_root)
    except SchemaViolationError:
        return False
    return True


def validate(instance: Any, schema: dict[str, Any]) -> None:
    """Validate ``instance`` or raise :class:`SchemaViolationError`."""
    _validate(instance, schema, schema)
