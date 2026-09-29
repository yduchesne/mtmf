//! Private MTMF permission-engine crate root.
//!
//! The crate is the deterministic in-memory permission-policy kernel for
//! MTMF: a detached native policy model (`model.rs`), SYSTEM Action/
//! Permission URN parsers (`urn.rs`), exact/wildcard single-Permission
//! matching with match specificity (`matcher.rs`), a complete
//! policy-decision algorithm (`evaluator.rs`): one exact Action against
//! zero or more already-applicable PermissionSets, maximum specificity
//! selection, lower-specificity elimination, PermissionSet effect
//! propagation, equal-specificity DENY precedence, default DENY, and a
//! deterministic aggregate result - inside the private native kernel
//! only. (PR 8G experiment only) an indexed compiled-policy module
//! (`compiled_policy.rs`) compiles already-applicable PermissionSets
//! once into exact/wildcard effect-aggregate maps for repeated
//! scan-free evaluation; it is experimental and never used by a
//! production authorization path.
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
//! small primitive bridges (a matcher fact bridge and an evaluator
//! bridge). Inputs are detached primitive values only: no live MTMF
//! Python domain object crosses the FFI boundary and no JSON
//! serialization carries policy. Malformed/incoherent native input or
//! output is an infrastructure failure, never a policy decision.

use pyo3::prelude::*;

mod compiled_policy;
mod evaluator;
mod matcher;
mod model;
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

/// Python module: private `_mtmf_permission_engine` surface.
///
/// Exposes the deterministic capability API, the smallest primitive
/// single-Permission matcher bridge, a primitive PermissionSet
/// evaluator bridge, and (PR 8G experiment only) an opaque
/// compiled-policy object bridge. No policy classes are exposed and
/// nothing here authorizes: Python determines which policy is
/// applicable.
#[pymodule]
mod _mtmf_permission_engine {
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;

    use crate::compiled_policy::CompiledPolicy;
    use crate::evaluator::{DenyReason, EvaluationDecision, EvaluationResult};
    use crate::matcher::{MatchResult, MatchSpecificity, match_permission_urns};
    use crate::model::{ActionInput, PermissionEffect, PermissionInput, PermissionSetInput};
    use crate::native_engine_version;

    /// Return the native engine capability version as a Python `str`.
    ///
    /// Deterministic and side-effect-free. Accepts no domain objects,
    /// parses no URNs, and evaluates no Actions: it only proves that the
    /// native module loaded.
    #[pyfunction]
    fn engine_version() -> PyResult<String> {
        Ok(native_engine_version().to_string())
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

    /// Map a native [`EvaluationResult`] onto the documented primitive
    /// 5-tuple. Shared by the scan evaluator bridge and the compiled
    /// policy object so both emit exactly the same evidence texts.
    fn native_evaluation_result(evaluation: EvaluationResult) -> NativeEvaluationResult {
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

    /// Convert the primitive `(effect, [permission URNs])` sequence
    /// into detached [`PermissionSetInput`] values, rejecting unknown
    /// effects exactly like the scan evaluator bridge.
    fn parse_primitive_sets(
        permission_sets: Vec<(String, Vec<String>)>,
    ) -> PyResult<Vec<PermissionSetInput>> {
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
        Ok(sets)
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
        let sets = parse_primitive_sets(permission_sets)?;
        let action = ActionInput {
            action_urn: action_urn.to_string(),
        };
        match crate::evaluator::evaluate(&action, &sets) {
            Ok(evaluation) => Ok(native_evaluation_result(evaluation)),
            Err(error) => {
                let description = error.describe();
                Err(PyValueError::new_err(format!(
                    "invalid MTMF URN: {description}"
                )))
            }
        }
    }

    /// Opaque compiled-policy native object (PR 8G experiment only).
    ///
    /// Constructed by `compile_policy`; frozen (immutable from
    /// Python), private fields, no setters, no mutable map exposure.
    /// Lifetime for 8G is only construct -> evaluate zero or more
    /// times -> drop; there is no registry, cache, serialization, or
    /// invalidation mechanism. Evaluation is deterministic and never
    /// mutates the compiled policy.
    #[pyclass(module = "_mtmf_permission_engine", frozen)]
    struct NativeCompiledPolicy {
        policy: CompiledPolicy,
    }

    #[pymethods]
    impl NativeCompiledPolicy {
        /// Evaluate one exact Action URN against the compiled policy.
        ///
        /// Returns the same documented primitive 5-tuple as the scan
        /// evaluator bridge. Parses the single Action per call and
        /// performs indexed lookups; it never re-parses Permissions,
        /// never scans the maps or the original policy, and never
        /// mutates the object. A malformed Action URN raises
        /// `ValueError` (a parsing failure, never a policy decision).
        fn evaluate(&self, action_urn: String) -> PyResult<NativeEvaluationResult> {
            match self.policy.evaluate(&action_urn) {
                Ok(evaluation) => Ok(native_evaluation_result(evaluation)),
                Err(error) => Err(PyValueError::new_err(error.describe())),
            }
        }
    }

    /// Compile already-applicable PermissionSets once (PR 8G
    /// experiment only).
    ///
    /// The primitive input shape is identical to `evaluate`: a
    /// sequence of `(effect, permissions)` pairs. Compilation performs
    /// every one-time policy cost (URN parsing/validation, exact vs
    /// wildcard classification, effect aggregation, index construction)
    /// and returns an opaque immutable object whose `evaluate` method
    /// handles repeated Actions without resending, reparsing, sorting,
    /// or scanning policy.
    ///
    /// Unknown effects and malformed Permission URNs raise `ValueError`
    /// and never produce a usable policy object; empty policy is valid.
    #[pyfunction]
    fn compile_policy(
        permission_sets: Vec<(String, Vec<String>)>,
    ) -> PyResult<NativeCompiledPolicy> {
        let sets = parse_primitive_sets(permission_sets)?;
        let policy = CompiledPolicy::compile(&sets)
            .map_err(|error| PyValueError::new_err(error.describe()))?;
        Ok(NativeCompiledPolicy { policy })
    }
}

#[cfg(test)]
mod tests {
    use crate::{ENGINE_VERSION, native_engine_version};

    #[test]
    fn version_is_the_static_capability_constant() {
        assert_eq!(native_engine_version(), ENGINE_VERSION);
    }

    #[test]
    fn version_is_deterministic_across_calls() {
        assert_eq!(native_engine_version(), native_engine_version());
    }
}
