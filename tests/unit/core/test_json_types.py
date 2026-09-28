"""Unit tests for the JSON/extension typing foundation."""

from mtmf_core.domain import JsonObject, JsonValue, new_extension


def test_fresh_extension_is_empty_object() -> None:
    assert new_extension() == {}


def test_extensions_are_independent_objects() -> None:
    first = new_extension()
    second = new_extension()
    assert first == {}
    assert second == {}
    assert first is not second


def test_mutating_one_extension_does_not_affect_another() -> None:
    first = new_extension()
    second = new_extension()
    first["owner"] = "app-a"
    assert second == {}


def test_extension_holds_nested_json_values() -> None:
    extension: JsonObject = {
        "text": "demo",
        "integer": 3,
        "float": 1.5,
        "boolean": True,
        "null": None,
        "list": [1, "two", None, {"key": "value"}],
        "nested": {"deep": {"items": [False, {"x": 1}]}},
    }
    assert extension["nested"]["deep"]["items"][1] == {"x": 1}


def test_json_value_typing_accepts_object() -> None:
    value: JsonValue = {"a": [1, None, "b"]}
    assert value["a"][2] == "b"


def test_top_level_extension_is_object_shaped() -> None:
    # The domain-level extension is always a JSON object; None is not a
    # valid top-level representation.
    assert isinstance(new_extension(), dict)
