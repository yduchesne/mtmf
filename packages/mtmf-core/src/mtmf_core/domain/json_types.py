"""Recursive JSON typing foundation for application extension data.

The top-level extension value is always a JSON object; nested values may
contain JSON ``null`` (``None``). ``new_extension()`` returns an
independent dictionary on every call so no mutable default is ever
shared between instances.
"""

from __future__ import annotations

type JsonScalar = str | int | float | bool | None

type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

type JsonObject = dict[str, JsonValue]


def new_extension() -> JsonObject:
    """Return a fresh, empty extension JSON object."""
    return {}
