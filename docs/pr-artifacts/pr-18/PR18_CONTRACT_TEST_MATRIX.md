# PR 18 — Contract Test Matrix

All CL-U rows are exercised by the **real production client** with a
deterministic `httpx.MockTransport` and injected fake clocks. No fake PDP
decision engine exists. Run:

```bash
uv run --no-sync pytest tests/unit/client -q
# 122 passed (74 test functions; parametrized edge variants)
```

| ID | Scenario | Test(s) | Result |
| --- | --- | --- | --- |
| CL-U01 | Package import in isolated wheel | `test_cl_u01_import_graph_has_no_forbidden_dependencies`, `test_cl_u01_dependency_metadata_is_http_only` | PASS |
| CL-U02 | Valid immutable config; no network at construction | `test_cl_u02_valid_config_constructs_without_network`, `test_cl_u02_config_defaults_are_conservative`, `test_cl_u02_rejects_invalid_values`, `test_cl_u02_application_id_requires_non_nil_uuid`, `test_config_is_immutable` | PASS |
| CL-U03 | HTTP URL, userinfo, fragment rejected pre-network | `test_cl_u03_rejects_unsafe_endpoints`, `test_cl_u03_trailing_slash_is_normalized` | PASS |
| CL-U04 | Missing/unsafe/empty secret reference | `test_cl_u04_requires_exactly_one_secret_source`, `test_cl_u04_rejects_missing_and_unsafe_secret_files`, `test_cl_u04_secret_file_read_is_bounded_and_redacted`, `test_cl_u04_empty_secret_file_fails_closed`, `test_cl_u04_secret_provider_repr_is_suppressed`, `test_cl_u04_ca_bundle_must_be_a_regular_file`, `test_cl_u04_secret_file_must_be_a_pathlib_path`, `test_cl_u04_unreadable_secret_file_fails_closed` | PASS |
| CL-U05 | First client-credentials request | `test_cl_u05_first_grant_uses_exact_client_credentials_request` | PASS |
| CL-U06 | Scope/audience only when configured | `test_cl_u06_scope_and_audience_only_when_configured` | PASS |
| CL-U07 | Reuse unexpired service token | `test_cl_u07_unexpired_token_is_reused` | PASS |
| CL-U08 | Proactive renewal at threshold; no refresh token | `test_cl_u08_proactive_renewal_at_threshold_without_refresh_token` | PASS |
| CL-U09 | Concurrent calls single-flight renewal | `test_cl_u09_concurrent_evaluation_triggers_single_flight_renewal` | PASS |
| CL-U10 | Token endpoint timeout/500/429; no authorization POST | `test_cl_u10_token_endpoint_failure_is_typed_and_no_authorization_post`, `test_cl_u10_token_endpoint_timeout_is_typed`, `test_cl_u10_unexpected_token_content_type_is_rejected` | PASS |
| CL-U11 | Malformed/oversized/duplicate token JSON; no token retained | `test_cl_u11_malformed_token_json_is_rejected`, `test_cl_u11_oversized_token_reply_is_rejected`, `test_cl_u11_no_token_retained_after_failure`, `test_cl_u11_non_finite_token_number_is_rejected` | PASS |
| CL-U12 | Invalid `token_type`/`expires_in`/token | `test_cl_u12_invalid_token_fields_are_rejected` | PASS |
| CL-U13 | Token endpoint redirect; no credential forwarding | `test_cl_u13_token_endpoint_redirect_is_not_followed` | PASS |
| CL-U14 | Exact MTMF service/user headers | `test_cl_u14_exact_headers_and_no_credentials_in_body` | PASS |
| CL-U15 | Missing user token / trusted actor binding | `test_cl_u15_missing_user_token_is_rejected_before_post`, `test_cl_u15_wrong_context_and_tenant_are_rejected_before_post` | PASS |
| CL-U16 | Exact v1 JSON, duplicates, order, 1–100 bound | `test_cl_u16_exact_json_preserves_order_and_duplicates`, `test_cl_u16_hundred_action_bound_is_preserved` | PASS |
| CL-U17 | Successful mixed ALLOW/DENY → one snapshot | `test_cl_u17_mixed_allow_deny_creates_one_snapshot` | PASS |
| CL-U18 | Reordered/omitted/added decision rejected | `test_cl_u18_reordered_decisions_are_rejected`, `test_cl_u18_omitted_or_added_decisions_are_rejected` | PASS |
| CL-U19 | Tenant/Organization mismatch rejected | `test_cl_u19_tenant_and_organization_mismatch_are_rejected` | PASS |
| CL-U20 | 200 malformed/duplicate/unknown-field JSON | `test_cl_u20_malformed_duplicate_and_unknown_field_json_are_rejected` | PASS |
| CL-U21 | Bad reason/effect, version, timestamp | `test_cl_u21_bad_effect_reason_version_timestamp_are_rejected` | PASS |
| CL-U22 | 401/403/429/503/error envelope typed failure | `test_cl_u22_error_envelopes_map_to_typed_failures` | PASS |
| CL-U23 | Unexpected/malformed non-200 → protocol failure | `test_cl_u23_malformed_or_unexpected_non_200_is_protocol_failure` | PASS |
| CL-U24 | Eligible 401 expiry retry | **NOT APPLICABLE — deferred by contract** (no machine-readable service-token-expiry signal; see `PR18_FAILURES_AND_DEVIATIONS.md`) | N/A |
| CL-U25 | Ambiguous 401/403/timeout/503 → no retry | `test_cl_u25_no_authorization_retry_for_ambiguous_failures` | PASS |
| CL-U26 | Retry exhaustion fails closed, max two POSTs | **NOT APPLICABLE** — no retry path exists; `CL-U25` proves exactly one POST | N/A |
| CL-U27 | Exact ALLOW occurrence | `test_cl_u27_exact_allow_occurrence_is_allowed` | PASS |
| CL-U28 | DENY/unknown/absent occurrence | `test_cl_u28_deny_unknown_and_absent_occurrence_deny` | PASS |
| CL-U29 | Duplicate semantic ambiguity requires occurrence id | `test_cl_u29_duplicate_semantic_occurrences_require_request_id` | PASS |
| CL-U30 | Cross-Application / cross-client-instance replay | `test_cl_u30_cross_application_and_cross_client_replay_deny` | PASS |
| CL-U31 | Cross-actor/session replay | `test_cl_u31_cross_actor_and_session_replay_deny` | PASS |
| CL-U32 | Cross-Tenant/Organization replay | `test_cl_u32_cross_tenant_and_organization_replay_deny` | PASS |
| CL-U33 | Cross-resource kind/type/id replay | `test_cl_u33_cross_resource_replay_denies` | PASS |
| CL-U34 | Capability ALLOW used for object | `test_cl_u34_capability_allow_cannot_be_used_for_an_object` | PASS |
| CL-U35 | Expiry boundary, monotonic advance | `test_cl_u35_monotonic_expiry_boundary` | PASS |
| CL-U36 | Wall skew/jumps, future-issued | `test_cl_u36_future_issued_and_already_expired_are_rejected`, `test_cl_u36_wall_clock_uncertainty_and_jumps`, `test_cl_u36_post_issue_wall_jumps_do_not_change_monotonic_validity` | PASS |
| CL-U37 | 15 s sensitive / 60 s default / 300 s max; no extension | `test_cl_u37_no_extension_and_universal_sensitive_cap` | PASS |
| CL-U38 | Token refresh does not extend snapshot | `test_cl_u38_token_renewal_does_not_extend_snapshot` | PASS |
| CL-U39 | No implicit HTTP on helper calls | `test_cl_u39_helpers_never_call_the_network` | PASS |
| CL-U40 | Exception/repr/log redaction | `test_cl_u40_tokens_and_secrets_are_redacted_from_failures`, `test_cl_u42_token_failure_is_redacted`, `test_snapshot_repr_is_redacted` | PASS |
| CL-U41 | Oversized/wrong content-type/redirect | `test_cl_u41_oversized_response_is_rejected`, `test_cl_u41_wrong_content_type_is_rejected`, `test_cl_u41_redirect_is_not_followed` | PASS |
| CL-U42 | Close/context-manager lifecycle | `test_cl_u42_close_and_context_manager_lifecycle` | PASS |
| CL-U43 | Token cache isolation across instances | `test_cl_u43_service_token_cache_is_isolated_per_client` | PASS |
| CL-U44 | Monotonic rollback/anomaly | `test_cl_u44_monotonic_rollback_denies` | PASS |
| CL-U45 | Tampered/reconstructed user snapshot | `test_cl_u45_tampered_snapshot_is_never_accepted`, `test_cl_u45_non_snapshot_objects_deny`, `test_snapshot_direct_construction_is_guarded` | PASS |

Additional helper tests: `test_snapshot_properties_and_context_validation`,
`test_module_helpers_default_deny_on_none`.

**Coverage of `packages/mtmf-client` from the unit suite:** 92% (see the
final acceptance report for the workspace total).
