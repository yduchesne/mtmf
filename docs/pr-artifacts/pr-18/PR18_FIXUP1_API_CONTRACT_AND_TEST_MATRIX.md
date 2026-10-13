# PR 18 Fixup 1 — API Contract and Test Matrix

## 1. Fixed public API contract

Both the `mtmf_client.snapshot` module functions and the
`HttpMtmfClient` methods now have these signatures (exact):

```python
def is_allowed(
    snapshot: AuthorizationSnapshot | None,
    *,
    context: TrustedActorContext,
    action: str,
    resource: ResourceTarget,
    request_id: str | None = None,
) -> bool: ...

def require(
    snapshot: AuthorizationSnapshot | None,
    *,
    context: TrustedActorContext,
    action: str,
    resource: ResourceTarget,
    request_id: str | None = None,
) -> None: ...
```

There is no overload and no backward-compatibility fallback. Omitting
`action` or `resource` raises a plain Python `TypeError` before any snapshot
is read. A missing resource is never a wildcard. Capability checks must pass
`ResourceTarget(kind=ResourceKind.CAPABILITY)` explicitly.

## 2. Lookup algorithm

1. `action` must be a `str`; `resource` must be a
   `mtmf_api.authorization.ResourceTarget`. Any other runtime value returns
   no match (`False` / `AuthorizationDenied`).
2. With `request_id`: the id must be a nonempty `str`; exactly one stored
   occurrence must have that id **and** the exact Action/ResourceTarget;
   otherwise no match.
3. Without `request_id`: occurrences matching **both** Action and
   ResourceTarget must be unique. Zero or multiple matches deny.
4. Only the corresponding decision of an already-conformant ordered
   snapshot is returned. `ALLOW` requires `AuthorizationEffect.ALLOW` with
   `DecisionReason.PERMITTED`.
5. Trusted-context equality, monotonic expiry, private provenance,
   client-instance binding and no-I/O behavior are preserved unchanged.

**PEP responsibility:** the consumer must derive the checked
`ResourceTarget` from the actual object being accessed, not copy a
previously authorized target by correlation id. A matching tuple proves only
that the previously evaluated Action/ResourceTarget was `ALLOW`; the
application's own row/Tenant predicate remains a separate mandatory step.

## 3. Compatibility break (pre-merge, intentional)

This is a deliberate breaking change to a not-yet-released API. Every
in-repository call site was migrated to pass the exact originally evaluated
Action and ResourceTarget:

- `tests/unit/client/test_client_snapshot.py`, `test_client_transport.py`
- `tests/integration/postgres/test_pr18_live_client.py` (CL-I01–I18)
- `packages/mtmf-client/README.md` example and new binding section

No assertion was deleted or relaxed; no expected DENY was changed to ALLOW.

## 4. FX-U matrix — required cases

Tests live in `tests/unit/client/test_client_resource_binding.py`. Each row
is one test function invoking the real public helper/client method with
deterministic fake HTTP transport and clocks.

| ID | Test function | Result |
| --- | --- | --- |
| FX-U01 | `test_fx_u01_exact_allow_returns_and_require_passes` | PASS |
| FX-U02 | `test_fx_u02_request_id_with_wrong_resource_denies` | PASS |
| FX-U03 | `test_fx_u03_same_resource_wrong_action_denies` | PASS |
| FX-U04 | `test_fx_u04_unique_action_resource_without_request_id_allows` | PASS |
| FX-U05 | `test_fx_u05_duplicate_action_resource_without_request_id_denies` | PASS |
| FX-U06 | `test_fx_u06_duplicate_occurrences_explicit_allow_id_allows_only_exact` | PASS |
| FX-U07 | `test_fx_u07_duplicate_occurrences_explicit_deny_id_denies` | PASS |
| FX-U08 | `test_fx_u08_request_id_only_module_helpers_raise_type_error` | PASS |
| FX-U09 | `test_fx_u09_request_id_and_action_only_module_helpers_raise_type_error` | PASS |
| FX-U10 | `test_fx_u10_action_only_module_helpers_raise_type_error` | PASS |
| FX-U11 | `test_fx_u11_client_methods_require_action_and_resource` | PASS |
| FX-U12 | `test_fx_u12_explicit_capability_matches_capability` | PASS |
| FX-U13 | `test_fx_u13_capability_vs_application_owned_cross_use_denies` | PASS |
| FX-U14 | `test_fx_u14_different_application_owned_type_denies` | PASS |
| FX-U15 | `test_fx_u15_different_mtmf_owned_type_or_id_denies` | PASS |
| FX-U16 | `test_fx_u16_wrong_context_denies` | PASS |
| FX-U17 | `test_fx_u17_expired_and_rollback_deny_without_http` | PASS |
| FX-U18 | `test_fx_u18_missing_snapshot_and_malformed_arguments_deny` | PASS |
| FX-U19 | `test_fx_u19_wrong_client_provenance_denies_client_methods` | PASS |
| FX-U20 | `test_fx_u20_unknown_action_and_policy_deny` | PASS |
| FX-U21 | `test_fx_u21_require_matches_is_allowed_for_every_case` | PASS |
| FX-U22 | `test_fx_u22_after_positive_decision_wrong_resource_with_same_id_denies` | PASS |
| FX-U23 | `test_fx_u23_two_resources_same_action_lookup_returns_only_supplied` | PASS |
| FX-U24 | `test_fx_u24_repeated_local_checks_never_touch_the_network` | PASS |
| FX-U25 | `test_fx_u25_caller_must_supply_the_current_object_target` | PASS |
| FX-U26 | `test_fx_u26_token_renewal_preserves_original_snapshot_deadline` | PASS |

Run:

```bash
uv run --no-sync pytest tests/unit/client -q --no-cov
# 148 passed (122 migrated previous cases + 26 FX-U cases)
```

## 5. Runtime-invalid vs missing-argument distinction

- Missing mandatory keyword (`action`/`resource`) → `TypeError` (FX-U08–U11).
- Supplied but runtime-invalid (`action` not `str`, `resource` not a
  `ResourceTarget`, malformed `request_id`) → no match / deny, never
  `TypeError` (FX-U18).
