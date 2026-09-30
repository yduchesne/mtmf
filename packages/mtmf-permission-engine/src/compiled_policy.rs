//! Compiled-policy indexed evaluation (PR 8G experiment).
//!
//! PR 8G tests a specific architectural hypothesis: compile
//! already-applicable policy once into an immutable indexed native
//! representation, then evaluate many Actions without repeatedly
//! traversing Roles/PermissionSets, retransferring policy between
//! Python and Rust, reparsing Permission URNs, or scanning every
//! Permission.
//!
//! This is an **experiment**, not a production cutover. The production
//! path remains `Authorizer() -> RustPermissionEvaluator ->
//! native_evaluate(action, policy)` from `evaluator.rs`, and the
//! Python `Authorizer`/`RustPermissionEvaluator` are unchanged by this
//! module. Nothing here retrieves session, Tenant, membership,
//! assignment, stewardship, or delegation context, and no I/O exists.
//!
//! Compilation consumes the existing PR 8E detached primitive
//! representation ([`PermissionSetInput`]) and performs every
//! one-time cost: Permission URN parsing/validation, classification as
//! EXACT or QUALIFIER_WILDCARD, effect aggregation by semantic lookup
//! key, and construction of two immutable index maps.
//!
//! ```text
//! exact:
//!   (namespace, resource, verb, qualifier) -> EffectAggregate
//! wildcard:
//!   (namespace, resource, verb) -> EffectAggregate
//! ```
//!
//! Evaluation parses the single Action URN, performs at most one
//! EXACT-map lookup and at most one WILDCARD-map lookup, and never
//! scans either map. There is **no sorted-list contract**: compilation
//! owns normalization, the caller supplies ordinary applicable
//! Roles/PermissionSets, and correctness never depends on caller
//! ordering. Duplicates are non-voting: compilation collapses
//! duplicate semantic entries into one [`EffectAggregate`].
//!
//! Malformed compilation input (malformed Permission URNs, wildcard
//! misuse, unsupported namespace) fails explicitly through
//! [`CompiledPolicyError::UrnParse`] and never produces a usable
//! policy. Unknown effects cannot reach this module in typed form
//! ([`PermissionEffect`] has exactly ALLOW/DENY); the Python boundary
//! rejects unknown effect text before conversion.

use std::collections::HashMap;

use crate::evaluator::EvaluationResult;
use crate::matcher::MatchSpecificity;
use crate::model::{PermissionEffect, PermissionSetInput};
use crate::urn::{UrnParseError, parse_action_urn, parse_permission_urn};

/// The pre-aggregated effect evidence for one semantic policy key.
///
/// Duplicates do not vote: a key carries at most one
/// [`EffectAggregate`], mutated only by OR-accumulating the two flags
/// while compiling. Every stored aggregate has at least one flag set
/// (every stored key originated from at least one parsed Permission).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectAggregate {
    /// Whether an ALLOW effect existed on the aggregated key.
    pub matched_allow: bool,
    /// Whether a DENY effect existed on the aggregated key.
    pub matched_deny: bool,
}

impl EffectAggregate {
    fn new() -> Self {
        Self {
            matched_allow: false,
            matched_deny: false,
        }
    }

    /// OR-accumulate one Permission effect into the aggregate.
    ///
    /// This is the whole duplicate-collapsing compilation step: adding
    /// an ALLOW to an existing ALLOW changes nothing, adding a DENY on
    /// the same key flips on `matched_deny`, and so on.
    fn accumulate(&mut self, effect: PermissionEffect) {
        match effect {
            PermissionEffect::Allow => self.matched_allow = true,
            PermissionEffect::Deny => self.matched_deny = true,
        }
    }

    /// True when the aggregate is coherent (carries at least one flag).
    fn coherent(self) -> bool {
        self.matched_allow || self.matched_deny
    }
}

/// The semantic key of an EXACT permission:
/// `(namespace, resource, verb, qualifier)`.
///
/// A plain record over validated component text; only the `system`
/// definition namespace parses today, but the component is carried for
/// structural parity with the Python reference matcher.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExactKey {
    pub namespace: String,
    pub resource: String,
    pub verb: String,
    pub qualifier: String,
}

/// The semantic key of a QUALIFIER_WILDCARD permission:
/// `(namespace, resource, verb)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WildcardKey {
    pub namespace: String,
    pub resource: String,
    pub verb: String,
}

/// Native compilation/evaluation failure channel.
///
/// Failures are classified infrastructure failures: a malformed policy
/// URN during compilation, a malformed Action URN during evaluation, or
/// an incoherent compiled entry. None of these is ever a policy
/// DECISION (`ALLOW`/`NO_MATCH`/`MATCHED_DENY`), and there is no
/// automatic Python fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledPolicyError {
    /// A policy or Action URN failed parsing/validation.
    UrnParse(UrnParseError),
    /// Evaluation reached a compiled entry with neither flag set.
    ///
    /// Structurally impossible under the current compiler (every stored
    /// key originates from at least one parsed Permission); kept as an
    /// explicit fail-closed channel so an incoherent native state can
    /// never be emitted as a decision.
    IncoherentAggregate,
}

impl CompiledPolicyError {
    /// A stable human-readable description of the failure.
    pub fn describe(self) -> String {
        match self {
            Self::UrnParse(error) => format!("invalid MTMF URN: {}", error.describe()),
            Self::IncoherentAggregate => {
                "incoherent compiled policy entry (neither ALLOW nor DENY evidence)".to_string()
            }
        }
    }
}

impl From<UrnParseError> for CompiledPolicyError {
    fn from(error: UrnParseError) -> Self {
        Self::UrnParse(error)
    }
}

/// An immutable, opaque compiled permission policy.
///
/// Construction parses and validates every supplied Permission URN
/// exactly once, classifies each as EXACT or QUALIFIER_WILDCARD, and
/// OR-accumulates effects into per-key [`EffectAggregate`] values. The
/// result is two index maps with pre-aggregated effects.
///
/// Lifetime for PR 8G is only: construct -> evaluate zero or more
/// times -> drop. There is no registry, global cache, persistence,
/// serialization, pickling, ABI promise, or invalidation mechanism.
///
/// Empty policy is valid: it compiles to an object that returns
/// `DENY / NO_MATCH` for every Action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    exact: HashMap<ExactKey, EffectAggregate>,
    wildcard: HashMap<WildcardKey, EffectAggregate>,
}

/// Resolve one aggregated effect into the documented coherent
/// `EvaluationResult` evidence.
///
/// Equal-specificity DENY wins; otherwise a present ALLOW wins; an
/// incoherent aggregate (neither flag) fails closed as an error.
fn resolve_aggregate(
    specificity: MatchSpecificity,
    aggregate: &EffectAggregate,
) -> Result<EvaluationResult, CompiledPolicyError> {
    if !aggregate.coherent() {
        return Err(CompiledPolicyError::IncoherentAggregate);
    }
    if aggregate.matched_deny {
        Ok(EvaluationResult::matched_deny(
            specificity,
            aggregate.matched_allow,
        ))
    } else {
        Ok(EvaluationResult::allow(specificity))
    }
}

impl CompiledPolicy {
    /// Compile already-applicable PermissionSets into the indexed form.
    ///
    /// Performs every one-time policy cost: parsing/validating each
    /// Permission matcher URN (rejecting malformed URNs, wildcard
    /// misuse, and unsupported namespaces), classifying EXACT vs
    /// QUALIFIER_WILDCARD, OR-aggregating effects by semantic key, and
    /// constructing the two lookup maps.
    ///
    /// The caller-supplied order of PermissionSets and Permissions is
    /// irrelevant: duplicates are collapsed by construction, and the
    /// maps are semantic indexes, not sequences.
    pub fn compile(
        permission_sets: &[PermissionSetInput],
    ) -> Result<CompiledPolicy, CompiledPolicyError> {
        let mut exact: HashMap<ExactKey, EffectAggregate> = HashMap::new();
        let mut wildcard: HashMap<WildcardKey, EffectAggregate> = HashMap::new();
        for permission_set in permission_sets {
            let effect = permission_set.effect;
            for permission in &permission_set.permissions {
                let parsed = parse_permission_urn(&permission.permission_urn)?;
                if parsed.is_wildcard() {
                    wildcard
                        .entry(WildcardKey {
                            namespace: parsed.namespace,
                            resource: parsed.resource,
                            verb: parsed.verb,
                        })
                        .or_insert_with(EffectAggregate::new)
                        .accumulate(effect);
                } else {
                    exact
                        .entry(ExactKey {
                            namespace: parsed.namespace,
                            resource: parsed.resource,
                            verb: parsed.verb,
                            qualifier: parsed.qualifier,
                        })
                        .or_insert_with(EffectAggregate::new)
                        .accumulate(effect);
                }
            }
        }
        Ok(CompiledPolicy { exact, wildcard })
    }

    /// Evaluate one exact Action URN against the compiled policy.
    ///
    /// The Action is parsed per call ([`crate::urn::parse_action_urn`]);
    /// no Permission is re-parsed, no policy is re-scanned, and no
    /// original Permission data is consulted. At most one EXACT-map
    /// lookup and one WILDCARD-map lookup happen per evaluation.
    ///
    /// Semantics preserved exactly:
    ///
    /// - EXACT beats QUALIFIER_WILDCARD (lower specificity is discarded
    ///   before effects);
    /// - at equal specificity a DENY wins, otherwise a present ALLOW
    ///   wins;
    /// - no match -> `DENY / NO_MATCH`;
    /// - complete result evidence (`matched_specificity`,
    ///   `matched_allow`, `matched_deny`, deny reason);
    /// - a wildcard DENY can never defeat an exact ALLOW.
    ///
    /// Evaluation never mutates the compiled policy and is fully
    /// deterministic.
    pub fn evaluate(&self, action_urn: &str) -> Result<EvaluationResult, CompiledPolicyError> {
        let parsed = parse_action_urn(action_urn)?;
        let exact_key = ExactKey {
            namespace: parsed.namespace.clone(),
            resource: parsed.resource.clone(),
            verb: parsed.verb.clone(),
            qualifier: parsed.qualifier,
        };
        if let Some(aggregate) = self.exact.get(&exact_key) {
            return resolve_aggregate(MatchSpecificity::Exact, aggregate);
        }
        let wildcard_key = WildcardKey {
            namespace: parsed.namespace,
            resource: parsed.resource,
            verb: parsed.verb,
        };
        if let Some(aggregate) = self.wildcard.get(&wildcard_key) {
            return resolve_aggregate(MatchSpecificity::QualifierWildcard, aggregate);
        }
        Ok(EvaluationResult::no_match())
    }

    /// Report the number of distinct EXACT keys in the compiled policy.
    ///
    /// Test-only observability helper: no production code depends on
    /// this count.
    #[cfg(test)]
    pub fn exact_key_count(&self) -> usize {
        self.exact.len()
    }

    /// Report the number of distinct WILDCARD keys in the compiled
    /// policy.
    ///
    /// Test-only observability helper: no production code depends on
    /// this count.
    #[cfg(test)]
    pub fn wildcard_key_count(&self) -> usize {
        self.wildcard.len()
    }
}

/// Compile one deterministic policy and compare every sample with the
/// scan evaluator. Shared by the hand-authored parity tests.
#[cfg(test)]
fn assert_same_decision(sets: &[PermissionSetInput], action_urn: &str) {
    let scanned = crate::evaluator::evaluate(
        &crate::model::ActionInput {
            action_urn: action_urn.to_string(),
        },
        sets,
    )
    .expect("scan evaluator accepted the policy");
    let compiled = CompiledPolicy::compile(sets)
        .expect("compiler accepted the policy")
        .evaluate(action_urn)
        .expect("compiled evaluation accepted the Action");
    assert_eq!(
        compiled, scanned,
        "scan and compiled decisions diverged for {action_urn:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::{CompiledPolicy, CompiledPolicyError, EffectAggregate};
    use crate::compiled_policy::assert_same_decision;
    use crate::matcher::MatchSpecificity;
    use crate::model::{PermissionEffect, PermissionInput, PermissionSetInput};
    use crate::urn::UrnParseError;

    // Canonical URN texts.
    const ACTION_SET_ACTIVE: &str = "urn:mtmf:iam:actions:system:principal:set-active";
    const ACTION_SET_ALIAS: &str = "urn:mtmf:iam:actions:system:principal:set-alias";
    const ACTION_GET_OBJECT: &str = "urn:mtmf:iam:actions:system:principal:get-object";
    const PERM_SET_ACTIVE: &str = "urn:mtmf:iam:permissions:system:principal:set-active";
    const PERM_SET_ALIAS: &str = "urn:mtmf:iam:permissions:system:principal:set-alias";
    const PERM_SET_ANY: &str = "urn:mtmf:iam:permissions:system:principal:set-*";
    const PERM_GET_ANY: &str = "urn:mtmf:iam:permissions:system:principal:get-*";
    const PERM_GET_OBJECT: &str = "urn:mtmf:iam:permissions:system:principal:get-object";
    const PERM_TENANT_SET_ANY: &str = "urn:mtmf:iam:permissions:system:tenant:set-*";

    fn perm(value: &str) -> PermissionInput {
        PermissionInput {
            permission_urn: value.to_string(),
        }
    }

    fn allow_set(permissions: Vec<PermissionInput>) -> PermissionSetInput {
        PermissionSetInput {
            effect: PermissionEffect::Allow,
            permissions,
        }
    }

    fn deny_set(permissions: Vec<PermissionInput>) -> PermissionSetInput {
        PermissionSetInput {
            effect: PermissionEffect::Deny,
            permissions,
        }
    }

    /// The policy-independent expectation shortcuts (same states as the
    /// evaluator tests).
    fn expect_allow(specificity: MatchSpecificity) -> crate::evaluator::EvaluationResult {
        crate::evaluator::EvaluationResult::allow(specificity)
    }

    fn expect_no_match() -> crate::evaluator::EvaluationResult {
        crate::evaluator::EvaluationResult::no_match()
    }

    fn expect_matched_deny(
        specificity: MatchSpecificity,
        matched_allow: bool,
    ) -> crate::evaluator::EvaluationResult {
        crate::evaluator::EvaluationResult::matched_deny(specificity, matched_allow)
    }

    // --- 1. Empty policy ------------------------------------------------

    #[test]
    fn empty_policy_compiles_and_never_matches() {
        let compiled = CompiledPolicy::compile(&[]).unwrap();
        assert_eq!(compiled.exact_key_count(), 0);
        assert_eq!(compiled.wildcard_key_count(), 0);
        assert_eq!(
            compiled.evaluate(ACTION_SET_ACTIVE).unwrap(),
            expect_no_match(),
        );
        assert_eq!(
            compiled.evaluate(ACTION_GET_OBJECT).unwrap(),
            expect_no_match()
        );
    }

    #[test]
    fn empty_sets_compress_to_empty_policy() {
        // Valid but empty PermissionSets contribute nothing: the result
        // must behave exactly like zero policy.
        let compiled = CompiledPolicy::compile(&[allow_set(Vec::new())]).unwrap();
        assert_eq!(compiled.exact_key_count(), 0);
        assert_eq!(compiled.wildcard_key_count(), 0);
        assert_eq!(
            compiled.evaluate(ACTION_SET_ACTIVE).unwrap(),
            expect_no_match(),
        );
    }

    // --- 2/4. Single exact/wildcard ALLOW --------------------------------

    #[test]
    fn single_exact_allow() {
        assert_eq!(
            CompiledPolicy::compile(&[allow_set(vec![perm(PERM_SET_ACTIVE)])])
                .unwrap()
                .evaluate(ACTION_SET_ACTIVE)
                .unwrap(),
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn single_wildcard_allow() {
        assert_eq!(
            CompiledPolicy::compile(&[allow_set(vec![perm(PERM_SET_ANY)])])
                .unwrap()
                .evaluate(ACTION_SET_ACTIVE)
                .unwrap(),
            expect_allow(MatchSpecificity::QualifierWildcard),
        );
    }

    // --- 3/5. Single exact/wildcard DENY --------------------------------

    #[test]
    fn single_exact_deny() {
        assert_eq!(
            CompiledPolicy::compile(&[deny_set(vec![perm(PERM_SET_ACTIVE)])])
                .unwrap()
                .evaluate(ACTION_SET_ACTIVE)
                .unwrap(),
            expect_matched_deny(MatchSpecificity::Exact, false),
        );
    }

    #[test]
    fn single_wildcard_deny() {
        assert_eq!(
            CompiledPolicy::compile(&[deny_set(vec![perm(PERM_SET_ANY)])])
                .unwrap()
                .evaluate(ACTION_SET_ACTIVE)
                .unwrap(),
            expect_matched_deny(MatchSpecificity::QualifierWildcard, false),
        );
    }

    // --- 6. Exact over wildcard -------------------------------------------

    #[test]
    fn exact_allow_beats_wildcard_deny() {
        assert_eq!(
            CompiledPolicy::compile(&[
                deny_set(vec![perm(PERM_SET_ANY)]),
                allow_set(vec![perm(PERM_SET_ACTIVE)]),
            ])
            .unwrap()
            .evaluate(ACTION_SET_ACTIVE)
            .unwrap(),
            // The wildcard DENY must not survive into the final
            // evidence: matched_deny stays false.
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn exact_deny_beats_wildcard_allow() {
        assert_eq!(
            CompiledPolicy::compile(&[
                allow_set(vec![perm(PERM_SET_ANY)]),
                deny_set(vec![perm(PERM_SET_ACTIVE)]),
            ])
            .unwrap()
            .evaluate(ACTION_SET_ACTIVE)
            .unwrap(),
            expect_matched_deny(MatchSpecificity::Exact, false),
        );
    }

    // --- 7. Equal-specificity conflict -------------------------------------

    #[test]
    fn equal_exact_allow_and_deny_is_deny_with_both_flag_evidence() {
        assert_eq!(
            CompiledPolicy::compile(&[
                allow_set(vec![perm(PERM_SET_ACTIVE)]),
                deny_set(vec![perm(PERM_SET_ACTIVE)]),
            ])
            .unwrap()
            .evaluate(ACTION_SET_ACTIVE)
            .unwrap(),
            expect_matched_deny(MatchSpecificity::Exact, true),
        );
    }

    #[test]
    fn equal_wildcard_allow_and_deny_is_deny_with_both_flag_evidence() {
        assert_eq!(
            CompiledPolicy::compile(&[
                allow_set(vec![perm(PERM_SET_ANY)]),
                deny_set(vec![perm(PERM_SET_ANY)]),
            ])
            .unwrap()
            .evaluate(ACTION_SET_ACTIVE)
            .unwrap(),
            expect_matched_deny(MatchSpecificity::QualifierWildcard, true),
        );
    }

    // --- 8. Duplicates do not vote -----------------------------------------

    #[test]
    fn duplicate_exact_allow_is_still_allow() {
        assert_eq!(
            CompiledPolicy::compile(&[
                allow_set(vec![perm(PERM_SET_ACTIVE)]),
                allow_set(vec![perm(PERM_SET_ACTIVE)]),
            ])
            .unwrap()
            .evaluate(ACTION_SET_ACTIVE)
            .unwrap(),
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn duplicate_exact_deny_is_still_deny() {
        assert_eq!(
            CompiledPolicy::compile(&[
                deny_set(vec![perm(PERM_SET_ACTIVE)]),
                deny_set(vec![perm(PERM_SET_ACTIVE)]),
            ])
            .unwrap()
            .evaluate(ACTION_SET_ACTIVE)
            .unwrap(),
            expect_matched_deny(MatchSpecificity::Exact, false),
        );
    }

    #[test]
    fn duplicate_allow_cannot_outweigh_equal_deny() {
        assert_eq!(
            CompiledPolicy::compile(&[
                allow_set(vec![perm(PERM_SET_ACTIVE)]),
                allow_set(vec![perm(PERM_SET_ACTIVE)]),
                deny_set(vec![perm(PERM_SET_ACTIVE)]),
            ])
            .unwrap()
            .evaluate(ACTION_SET_ACTIVE)
            .unwrap(),
            expect_matched_deny(MatchSpecificity::Exact, true),
        );
    }

    #[test]
    fn duplicate_same_semantic_key_collapses_to_one_map_entry() {
        // Five copies of the same exact Permission must collapse into a
        // single EXACT key.
        let compiled = CompiledPolicy::compile(&[allow_set(vec![
            perm(PERM_SET_ACTIVE),
            perm(PERM_SET_ACTIVE),
            perm(PERM_SET_ACTIVE),
        ])])
        .unwrap();
        assert_eq!(compiled.exact_key_count(), 1);
        assert_eq!(compiled.wildcard_key_count(), 0);
    }

    // --- 9. Unrelated keys -------------------------------------------------

    #[test]
    fn unrelated_exact_and_wildcard_keys_are_no_match() {
        let compiled = CompiledPolicy::compile(&[
            allow_set(vec![perm(PERM_SET_ALIAS), perm(PERM_GET_OBJECT)]),
            deny_set(vec![perm(PERM_TENANT_SET_ANY)]),
        ])
        .unwrap();
        assert_eq!(
            compiled.evaluate(ACTION_SET_ACTIVE).unwrap(),
            expect_no_match(),
        );
    }

    // --- 10. No match ------------------------------------------------------

    #[test]
    fn verb_and_qualifier_mismatch_are_no_match() {
        let compiled = CompiledPolicy::compile(&[allow_set(vec![perm(PERM_GET_OBJECT)])]).unwrap();
        assert_eq!(
            compiled.evaluate(ACTION_SET_ACTIVE).unwrap(),
            expect_no_match()
        );
        let compiled = CompiledPolicy::compile(&[allow_set(vec![perm(PERM_SET_ACTIVE)])]).unwrap();
        assert_eq!(
            compiled.evaluate(ACTION_SET_ALIAS).unwrap(),
            expect_no_match()
        );
    }

    #[test]
    fn exact_key_does_not_leak_into_wildcard_lookup() {
        // An exact set-active key must not match an action with a
        // different qualifier through some implicit wildcard.
        let compiled = CompiledPolicy::compile(&[allow_set(vec![perm(PERM_SET_ACTIVE)])]).unwrap();
        assert_eq!(
            compiled.evaluate(ACTION_SET_ALIAS).unwrap(),
            expect_no_match()
        );
    }

    // --- 11. Deterministic repeated evaluation ------------------------------

    #[test]
    fn repeated_evaluation_is_identical() {
        let compiled = CompiledPolicy::compile(&[
            deny_set(vec![perm(PERM_SET_ANY)]),
            allow_set(vec![perm(PERM_SET_ACTIVE)]),
        ])
        .unwrap();
        let first = compiled.evaluate(ACTION_SET_ACTIVE).unwrap();
        for _ in 0..5 {
            assert_eq!(compiled.evaluate(ACTION_SET_ACTIVE).unwrap(), first);
        }
    }

    // --- 12. Input-order independence ----------------------------------------

    #[test]
    fn reversed_set_order_is_identical() {
        let forward = [
            allow_set(vec![perm(PERM_SET_ANY)]),
            deny_set(vec![perm(PERM_SET_ACTIVE)]),
        ];
        let reversed = [
            deny_set(vec![perm(PERM_SET_ACTIVE)]),
            allow_set(vec![perm(PERM_SET_ANY)]),
        ];
        let a = CompiledPolicy::compile(&forward).unwrap();
        let b = CompiledPolicy::compile(&reversed).unwrap();
        assert_eq!(
            a.evaluate(ACTION_SET_ACTIVE).unwrap(),
            b.evaluate(ACTION_SET_ACTIVE).unwrap(),
        );
        assert_eq!(a.exact_key_count(), b.exact_key_count());
        assert_eq!(a.wildcard_key_count(), b.wildcard_key_count());
    }

    #[test]
    fn reversed_permission_order_inside_a_set_is_identical() {
        let one = [allow_set(vec![
            perm(PERM_GET_OBJECT),
            perm(PERM_SET_ANY),
            perm(PERM_SET_ACTIVE),
        ])];
        let other = [allow_set(vec![
            perm(PERM_SET_ACTIVE),
            perm(PERM_SET_ANY),
            perm(PERM_GET_OBJECT),
        ])];
        let a = CompiledPolicy::compile(&one).unwrap();
        let b = CompiledPolicy::compile(&other).unwrap();
        assert_eq!(a, b);
    }

    // --- 13/15. Malformed input fails explicitly -----------------------------

    #[test]
    fn malformed_permission_urn_fails_compilation() {
        assert_eq!(
            CompiledPolicy::compile(&[allow_set(vec![perm("not-a-urn")])]),
            Err(CompiledPolicyError::UrnParse(UrnParseError::InvalidPrefix)),
        );
    }

    #[test]
    fn empty_permission_text_fails_compilation() {
        assert!(
            CompiledPolicy::compile(&[allow_set(vec![PermissionInput {
                permission_urn: String::new(),
            }])])
            .is_err()
        );
    }

    #[test]
    fn unsupported_namespace_fails_compilation() {
        assert_eq!(
            CompiledPolicy::compile(&[allow_set(vec![perm(
                "urn:mtmf:iam:permissions:tenant:principal:set-active",
            )])]),
            Err(CompiledPolicyError::UrnParse(
                UrnParseError::UnsupportedNamespace
            )),
        );
    }

    #[test]
    fn partial_wildcard_fails_compilation() {
        assert_eq!(
            CompiledPolicy::compile(&[allow_set(vec![perm(
                "urn:mtmf:iam:permissions:system:principal:set-act*ve",
            )])]),
            Err(CompiledPolicyError::UrnParse(
                UrnParseError::InvalidWildcard
            )),
        );
    }

    #[test]
    fn wildcard_resource_fails_compilation() {
        assert_eq!(
            CompiledPolicy::compile(&[allow_set(vec![perm(
                "urn:mtmf:iam:permissions:system:prin*cipal:set-*",
            )])]),
            Err(CompiledPolicyError::UrnParse(
                UrnParseError::WildcardNotAllowed
            )),
        );
    }

    #[test]
    fn malformed_action_fails_evaluation() {
        let compiled = CompiledPolicy::compile(&[allow_set(vec![perm(PERM_SET_ANY)])]).unwrap();
        assert_eq!(
            compiled.evaluate("not-a-urn"),
            Err(CompiledPolicyError::UrnParse(UrnParseError::InvalidPrefix)),
        );
    }

    #[test]
    fn wildcard_action_fails_evaluation() {
        // Actions are exact only: a wildcard Action is malformed input.
        let compiled = CompiledPolicy::compile(&[allow_set(vec![perm(PERM_SET_ANY)])]).unwrap();
        assert!(
            compiled
                .evaluate("urn:mtmf:iam:actions:system:principal:set-*")
                .is_err()
        );
    }

    #[test]
    fn malformed_input_never_becomes_no_match() {
        // A single malformed Permission alongside otherwise valid
        // policy fails compilation; it can never silently produce an
        // empty policy or a NO_MATCH decision.
        assert!(
            CompiledPolicy::compile(&[
                deny_set(vec![perm(PERM_GET_OBJECT)]),
                allow_set(vec![PermissionInput {
                    permission_urn: String::new(),
                }]),
            ])
            .is_err()
        );
    }

    // --- 16. Evaluation does not mutate policy --------------------------------

    #[test]
    fn policy_unchanged_by_evaluation() {
        let compiled = CompiledPolicy::compile(&[
            allow_set(vec![perm(PERM_SET_ANY)]),
            deny_set(vec![perm(PERM_SET_ACTIVE)]),
        ])
        .unwrap();
        let before = compiled.clone();
        for _ in 0..5 {
            let _ = compiled.evaluate(ACTION_SET_ACTIVE).unwrap();
            let _ = compiled.evaluate(ACTION_SET_ALIAS).unwrap();
            let _ = compiled.evaluate(ACTION_GET_OBJECT).unwrap();
        }
        assert_eq!(compiled, before);
        assert_eq!(compiled.exact_key_count(), before.exact_key_count());
        assert_eq!(compiled.wildcard_key_count(), before.wildcard_key_count());
    }

    // --- Effects are pre-aggregated and coherent ------------------------------

    #[test]
    fn effects_are_pre_aggregated_into_the_indexes() {
        // Two ALLOW + one DENY on the same exact key must collapse into
        // a single aggregate with both flags, never three entries.
        let compiled = CompiledPolicy::compile(&[
            allow_set(vec![perm(PERM_SET_ACTIVE)]),
            allow_set(vec![perm(PERM_SET_ACTIVE)]),
            deny_set(vec![perm(PERM_SET_ACTIVE)]),
        ])
        .unwrap();
        assert_eq!(compiled.exact_key_count(), 1);
        let aggregate = compiled
            .exact
            .get(&crate::compiled_policy::ExactKey {
                namespace: "system".to_string(),
                resource: "principal".to_string(),
                verb: "set".to_string(),
                qualifier: "active".to_string(),
            })
            .expect("aggregated key exists");
        assert_eq!(
            *aggregate,
            EffectAggregate {
                matched_allow: true,
                matched_deny: true,
            }
        );
    }

    #[test]
    fn aggregates_are_never_both_false() {
        let compiled = CompiledPolicy::compile(&[
            allow_set(vec![perm(PERM_SET_ANY), perm(PERM_GET_OBJECT)]),
            deny_set(vec![perm(PERM_SET_ALIAS)]),
        ])
        .unwrap();
        for aggregate in compiled.exact.values() {
            assert!(aggregate.coherent(), "exact aggregate must carry evidence");
        }
        for aggregate in compiled.wildcard.values() {
            assert!(
                aggregate.coherent(),
                "wildcard aggregate must carry evidence"
            );
        }
    }

    // --- 17. Large deterministic compiled policy ------------------------------

    #[test]
    fn large_deterministic_policy_compiles_and_evaluates() {
        // 100 distinct exact resources x 50 qualifiers = 5000 distinct
        // exact ALLOW keys, plus wildcard prefixes; no timing assertion.
        let mut permissions = Vec::new();
        for resource_index in 0..100 {
            for qualifier_index in 0..50 {
                permissions.push(perm(&format!(
                    "urn:mtmf:iam:permissions:system:resource{resource_index}:op-{qualifier_index}"
                )));
            }
        }
        let compiled = CompiledPolicy::compile(&[allow_set(permissions)]).unwrap();
        assert_eq!(compiled.exact_key_count(), 5000);
        assert_eq!(compiled.wildcard_key_count(), 0);
        let decided = compiled
            .evaluate("urn:mtmf:iam:actions:system:resource7:op-13")
            .unwrap();
        assert_eq!(decided, expect_allow(MatchSpecificity::Exact));
        assert_eq!(
            compiled
                .evaluate("urn:mtmf:iam:actions:system:resource7:op-999")
                .unwrap(),
            expect_no_match(),
        );
    }

    #[test]
    fn wildcard_only_policy_over_many_resources() {
        let mut permissions = Vec::new();
        for index in 0..25 {
            permissions.push(perm(&format!(
                "urn:mtmf:iam:permissions:system:resource{index}:do-*"
            )));
        }
        let compiled = CompiledPolicy::compile(&[deny_set(permissions)]).unwrap();
        assert_eq!(compiled.wildcard_key_count(), 25);
        let decided = compiled
            .evaluate("urn:mtmf:iam:actions:system:resource12:do-x")
            .unwrap();
        assert_eq!(
            decided,
            expect_matched_deny(MatchSpecificity::QualifierWildcard, false),
        );
    }

    // --- Scan-vs-compiled native semantic parity ------------------------------

    #[test]
    fn scan_and_compiled_agree_on_authored_cases() {
        let cases: Vec<(&str, Vec<PermissionSetInput>)> = vec![
            (ACTION_SET_ACTIVE, vec![]),
            (
                ACTION_SET_ACTIVE,
                vec![allow_set(vec![perm(PERM_SET_ACTIVE)])],
            ),
            (
                ACTION_SET_ACTIVE,
                vec![deny_set(vec![perm(PERM_SET_ACTIVE)])],
            ),
            (ACTION_SET_ACTIVE, vec![allow_set(vec![perm(PERM_SET_ANY)])]),
            (
                ACTION_SET_ACTIVE,
                vec![
                    allow_set(vec![perm(PERM_SET_ANY)]),
                    deny_set(vec![perm(PERM_SET_ACTIVE)]),
                ],
            ),
            (
                ACTION_SET_ACTIVE,
                vec![
                    deny_set(vec![perm(PERM_GET_OBJECT)]),
                    allow_set(vec![perm(PERM_SET_ACTIVE)]),
                    allow_set(vec![perm(PERM_SET_ACTIVE)]),
                ],
            ),
            (
                ACTION_SET_ALIAS,
                vec![
                    allow_set(vec![perm(PERM_SET_ANY)]),
                    deny_set(vec![perm(PERM_GET_ANY)]),
                ],
            ),
        ];
        for (action_urn, sets) in cases {
            assert_same_decision(&sets, action_urn);
        }
    }

    /// Tiny deterministic LCG so generated parity fuzz needs no third
    /// party: xorshift64* is compact and adequate for test generation.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn pick(&mut self, bound: usize) -> usize {
            debug_assert!(bound > 0);
            (self.next() % bound as u64) as usize
        }
    }

    #[test]
    fn scan_and_compiled_agree_on_generated_policy() {
        // 2000 deterministic random policies with duplicates, mixed
        // effects, exact/wildcard mixes, and random Actions. No timing.
        let mut random = Lcg(0x9E37_79B9_7F4A_7C15);
        let resources = ["principal", "tenant", "resource0", "resource1"];
        let verbs = ["set", "get", "delete", "do"];
        let qualifiers = ["active", "alias", "object", "x", "y"];
        for _ in 0..2000 {
            let mut sets: Vec<PermissionSetInput> = Vec::new();
            for _ in 0..random.pick(4) {
                let mut permissions = Vec::new();
                for _ in 0..random.pick(6) {
                    let resource = resources[random.pick(resources.len())];
                    let verb = verbs[random.pick(verbs.len())];
                    let qualifier = if random.next().is_multiple_of(4) {
                        "*"
                    } else {
                        qualifiers[random.pick(qualifiers.len())]
                    };
                    permissions.push(perm(&format!(
                        "urn:mtmf:iam:permissions:system:{resource}:{verb}-{qualifier}"
                    )));
                }
                if random.next().is_multiple_of(2) {
                    sets.push(allow_set(permissions));
                } else {
                    sets.push(deny_set(permissions));
                }
            }
            let resource = resources[random.pick(resources.len())];
            let verb = verbs[random.pick(verbs.len())];
            let qualifier = qualifiers[random.pick(qualifiers.len())];
            let action_urn = format!("urn:mtmf:iam:actions:system:{resource}:{verb}-{qualifier}");
            assert_same_decision(&sets, &action_urn);
        }
    }
}
