//! Private MTMF permission-engine crate root.
//!
//! The crate is the deterministic in-memory permission-policy kernel for
//! MTMF: a detached native policy model (`model.rs`), SYSTEM Action/
//! Permission URN parsers (`urn.rs`), exact/wildcard single-Permission
//! matching with match specificity (`matcher.rs`), and a complete
//! policy-decision algorithm (`evaluator.rs`): one exact Action against
//! zero or more already-applicable PermissionSets, maximum specificity
//! selection, lower-specificity elimination, PermissionSet effect
//! propagation, equal-specificity DENY precedence, default DENY, and a
//! deterministic aggregate result - inside the private native kernel
//! only.
//!
//! Rust evaluates policy only: it never retrieves session, Tenant,
//! membership, assignment, stewardship, or delegation context, and
//! performs no I/O (no PostgreSQL, `MtmfSpi`, repositories, network,
//! filesystem policy discovery, async runtime, background thread, or
//! cache).
//!
//! Rust does NOT determine applicable policy, consume Roles, retrieve
//! context, or persist anything: Python (the `Authorizer`) determines
//! which policy is applicable and supplies it detached. The `Authorizer`
//! defaults to the `RustPermissionEvaluator` seam and evaluates policy
//! through this kernel; the Python `PermissionEvaluator` remains the
//! semantic reference and systematic differential tests prove
//! equivalence.
//!
//! The only surface exposed to Python is the private PyO3 module plus
//! small primitive bridges (a matcher fact bridge, an evaluator bridge,
//! and an experimental msgspec/MessagePack semantic-buffer bridge).
//! Inputs are detached primitive values only: no live MTMF Python
//! domain object crosses the FFI boundary and no JSON serialization
//! carries policy. Malformed/incoherent native input or output is an
//! infrastructure failure, never a policy decision.
//!
//! Since PR 8F the crate also contains an experimental MessagePack
//! semantic-buffer boundary (`semantic.rs`): a single-buffer PyO3 entry
//! point (`evaluate_semantic_msgpack`) that decodes already-parsed
//! semantic wire components and converges on the same canonical
//! decision loop as the production URN path. It is benchmark-only and
//! never used by `Authorizer`/`RustPermissionEvaluator`.

use pyo3::prelude::*;

mod evaluator;
mod matcher;
mod model;
mod semantic;
mod urn;

/// Deterministic engine capability version reported by the native module.
///
/// The value is a static capability constant: it proves native
/// loading/build success only and asserts nothing about permission
/// semantics.
pub const ENGINE_VERSION: &str = "0.1.0";

/// Return the deterministic engine capability version.
///
/// Kept as a plain Rust function (independent of PyO3) so the value and
/// its determinism can be unit-tested by `cargo test` without touching
/// the FFI surface or a live Python interpreter.
pub fn native_engine_version() -> &'static str {
    ENGINE_VERSION
}

/// Return the compile-time native build profile.
///
/// `"debug"` for a `maturin develop`/`cargo` debug build and
/// `"release"` for an optimized release build. Exposed so benchmark
/// output can record which native build produced the measurements
/// (PR 8F section 24: debug and release builds can differ materially).
/// This is a provenance/capability fact, not a semantic capability.
pub fn native_build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// Python module: private `_mtmf_permission_engine` surface.
///
/// Exposes the deterministic capability API, the smallest primitive
/// single-Permission matcher bridge, and a primitive PermissionSet
/// evaluator bridge. No policy classes are exposed and nothing here
/// authorizes: Python determines which policy is applicable.
#[pymodule]
mod _mtmf_permission_engine {
    use std::borrow::Cow;

    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;

    use crate::evaluator::{DenyReason, EvaluationDecision};
    use crate::matcher::{MatchResult, MatchSpecificity, match_permission_urns};
    use crate::model::{ActionInput, PermissionEffect, PermissionInput, PermissionSetInput};
    use crate::{native_build_profile, native_engine_version};

    /// Return the native engine capability version as a Python `str`.
    ///
    /// Deterministic and side-effect-free. Accepts no domain objects,
    /// parses no URNs, and evaluates no Actions: it only proves that the
    /// native module loaded.
    #[pyfunction]
    fn engine_version() -> PyResult<String> {
        Ok(native_engine_version().to_string())
    }

    /// Return the compile-time native build profile as a Python `str`.
    ///
    /// `"debug"` (``maturin develop``/`cargo` debug builds) or
    /// `"release"` (optimized release builds). Benchmark output records
    /// this so debug and release characterization are never conflated.
    /// Deterministic and side-effect-free; not a semantic capability.
    #[pyfunction]
    fn build_profile() -> PyResult<String> {
        Ok(native_build_profile().to_string())
    }

    /// Match one exact Action URN against one Permission matcher URN.
    ///
    /// Primitive strings in; a primitive match fact out:
    ///
    /// - `"exact"` — exact qualifier match;
    /// - `"qualifier-wildcard"` — complete-qualifier `*` match;
    /// - `None` — valid input, no match.
    ///
    /// Malformed input raises `ValueError` (a parsing failure, distinct
    /// from a valid non-match). This function computes a match fact
    /// only: it never evaluates PermissionSet effects and never returns
    /// an ALLOW/DENY decision.
    #[pyfunction]
    fn match_permission(action_urn: String, permission_urn: String) -> PyResult<Option<String>> {
        match match_permission_urns(&action_urn, &permission_urn) {
            Ok(MatchResult::Match(MatchSpecificity::Exact)) => Ok(Some("exact".to_string())),
            Ok(MatchResult::Match(MatchSpecificity::QualifierWildcard)) => {
                Ok(Some("qualifier-wildcard".to_string()))
            }
            Ok(MatchResult::NoMatch) => Ok(None),
            Err(error) => {
                let description = error.describe();
                Err(PyValueError::new_err(format!(
                    "invalid MTMF URN: {description}"
                )))
            }
        }
    }

    /// The primitive native evaluation result shape:
    /// `(decision, matched_specificity, matched_allow, matched_deny,
    /// deny_reason)`.
    ///
    /// Aliased so the clippy type-complexity check stays satisfied
    /// without suppressing the lint.
    type NativeEvaluationResult = (String, Option<String>, bool, bool, Option<String>);

    /// Convert one canonical [`EvaluationResult`] into the primitive
    /// five-element aggregate returned through PyO3.
    fn to_native_evaluation(
        evaluation: &crate::evaluator::EvaluationResult,
    ) -> NativeEvaluationResult {
        let decision = match evaluation.decision {
            EvaluationDecision::Allow => "allow".to_string(),
            EvaluationDecision::Deny => "deny".to_string(),
        };
        let specificity = match evaluation.matched_specificity {
            None => None,
            Some(MatchSpecificity::Exact) => Some("exact".to_string()),
            Some(MatchSpecificity::QualifierWildcard) => Some("qualifier-wildcard".to_string()),
        };
        let reason = match evaluation.deny_reason {
            None => None,
            Some(DenyReason::NoMatch) => Some("no-match".to_string()),
            Some(DenyReason::MatchedDeny) => Some("matched-deny".to_string()),
        };
        (
            decision,
            specificity,
            evaluation.matched_allow,
            evaluation.matched_deny,
            reason,
        )
    }

    /// Evaluate one exact Action URN against already-applicable
    /// PermissionSets.
    ///
    /// Primitive input in; a primitive aggregate result out. The
    /// `permission_sets` argument is a sequence of `(effect,
    /// permissions)` pairs where `effect` is exactly `"allow"` or
    /// `"deny"` and `permissions` is a sequence of Permission matcher
    /// URN texts.
    ///
    /// The returned 5-tuple is:
    ///
    /// - decision: `"allow"` or `"deny"`;
    /// - matched specificity: `"exact"`, `"qualifier-wildcard"`, or
    ///   `None`;
    /// - `matched_allow`: whether an ALLOW existed at the maximum
    ///   specificity;
    /// - `matched_deny`: whether a DENY existed at the maximum
    ///   specificity;
    /// - deny reason: `"no-match"`, `"matched-deny"`, or `None` for an
    ///   ALLOW.
    ///
    /// Malformed Action/Permission URNs and unknown effects raise
    /// `ValueError`; neither is ever silently converted into a policy
    /// decision. This function evaluates *supplied* policy only - it
    /// receives no Role/Tenant/session/assignment data.
    #[pyfunction]
    fn evaluate(
        action_urn: String,
        permission_sets: Vec<(String, Vec<String>)>,
    ) -> PyResult<NativeEvaluationResult> {
        let mut sets = Vec::new();
        for (effect_text, permission_texts) in permission_sets {
            if effect_text == "allow" {
                sets.push(PermissionSetInput {
                    effect: PermissionEffect::Allow,
                    permissions: Vec::from_iter(permission_texts.into_iter().map(|text| {
                        PermissionInput {
                            permission_urn: text.to_string(),
                        }
                    })),
                });
            } else if effect_text == "deny" {
                sets.push(PermissionSetInput {
                    effect: PermissionEffect::Deny,
                    permissions: Vec::from_iter(permission_texts.into_iter().map(|text| {
                        PermissionInput {
                            permission_urn: text.to_string(),
                        }
                    })),
                });
            } else {
                return Err(PyValueError::new_err(format!(
                    "invalid PermissionSet effect {effect_text:?}; expected exactly 'allow' or 'deny'"
                )));
            }
        }
        let action = ActionInput {
            action_urn: action_urn.to_string(),
        };
        match crate::evaluator::evaluate(&action, &sets) {
            Ok(evaluation) => Ok(to_native_evaluation(&evaluation)),
            Err(error) => {
                let description = error.describe();
                Err(PyValueError::new_err(format!(
                    "invalid MTMF URN: {description}"
                )))
            }
        }
    }

    /// EXPERIMENTAL (PR 8F) single-payload semantic-buffer evaluation.
    ///
    /// Decodes one versioned MessagePack payload whose Action/Permission
    /// data are already-parsed semantic components (never complete MTMF
    /// URN texts), validates them, and evaluates through the same
    /// canonical decision loop as [`evaluate`]. Returns the same
    /// five-element primitive aggregate shape.
    ///
    /// The payload is accepted as a single bytes-like argument: `bytes`
    /// is borrowed by PyO3; a `bytearray`/`memoryview` is copied into
    /// an owned Rust value (`Cow<[u8]>`). MessagePack encode/decode
    /// remain serialization work: this path is not claimed to be
    /// zero-copy.
    ///
    /// This entry point is benchmark-only and deliberately NOT part of
    /// the production authorization path: `Authorizer` and
    /// `RustPermissionEvaluator` never call it. Malformed wire data
    /// raises `ValueError` and can never become ALLOW, NO_MATCH, or
    /// MATCHED_DENY.
    #[pyfunction]
    fn evaluate_semantic_msgpack(payload: Cow<'_, [u8]>) -> PyResult<NativeEvaluationResult> {
        match crate::semantic::evaluate_semantic_msgpack(&payload) {
            Ok(evaluation) => Ok(to_native_evaluation(&evaluation)),
            Err(error) => Err(PyValueError::new_err(format!(
                "invalid semantic MessagePack payload: {}",
                error.describe()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ENGINE_VERSION, native_build_profile, native_engine_version};

    #[test]
    fn version_is_the_static_capability_constant() {
        assert_eq!(native_engine_version(), ENGINE_VERSION);
    }

    #[test]
    fn version_is_deterministic_across_calls() {
        assert_eq!(native_engine_version(), native_engine_version());
    }

    #[test]
    fn build_profile_is_exactly_debug_or_release() {
        let profile = native_build_profile();
        assert!(matches!(profile, "debug" | "release"), "{profile}");
    }

    #[test]
    fn build_profile_is_deterministic_across_calls() {
        assert_eq!(native_build_profile(), native_build_profile());
    }
}
