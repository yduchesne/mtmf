//! Collection-level PermissionSet evaluation.
//!
//! This module implements the complete policy-decision algorithm of the
//! private Rust kernel: one exact [`ActionInput`] against zero or more
//! already-applicable detached [`PermissionSetInput`] values.
//!
//! The evaluator reuses the parser (`urn.rs`) and the single Permission
//! matcher (`matcher.rs`) - there is exactly one canonical
//! matcher and parser in the crate. It adds the collection-level
//! semantics:
//!
//! 1. every Permission of every supplied PermissionSet is matched
//!    against the parsed Action;
//! 2. only the matches at the maximum specificity survive;
//! 3. lower-specificity matches are discarded *before* any effect
//!    resolution, so a wildcard DENY can never defeat an exact ALLOW;
//! 4. each surviving match inherits the effect of its containing
//!    PermissionSet;
//! 5. among equally specific survivors, any DENY wins, else any ALLOW
//!    wins;
//! 6. no match at all means DENY.
//!
//! The evaluation is synchronous, deterministic, side-effect-free,
//! I/O-free, cache-free, and free of global mutable policy state.
//! PermissionSet order, Permission order, duplicate positions, and
//! duplicates themselves never change the result: duplicates create no
//! voting semantics and evaluation is set-like semantically even though
//! the input types are sequences.
//!
//! Malformed input is **not** a semantic policy DENY: an unparseable
//! Action or Permission URN makes the evaluation fail with a
//! [`UrnParseError`]. Valid but empty or non-matching policy produces
//! `DENY / NO_MATCH`.
//!
//! The documented applicability boundary is unchanged: Rust evaluates
//! *supplied* policy only. Nothing here knows about Tenant, Role,
//! membership, session, scope, stewardship, persistence, or network
//! services; Python (the `Authorizer`) decides which policy is
//! applicable and supplies it detached.

use crate::matcher::{MatchResult, MatchSpecificity, match_permission};
use crate::model::{ActionInput, PermissionEffect, PermissionSetInput};
use crate::urn::{
    ParsedActionUrn, ParsedPermissionUrn, UrnParseError, parse_action_urn, parse_permission_urn,
};

/// The explicit evaluation outcome for one Action.
///
/// Exactly `Allow` and `Deny` exist. There is no abstain/implicit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationDecision {
    Allow,
    Deny,
}

/// The coarse internal reason behind a DENY.
///
/// Categories are intentionally coarse and carry no PermissionSet,
/// Permission, or Role identity facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// No supplied Permission matched the Action.
    NoMatch,
    /// At least one DENY matched at the maximum specificity.
    MatchedDeny,
}

/// The deterministic aggregate result of evaluating one Action against
/// the supplied PermissionSets.
///
/// The fields mirror the evidence the Python reference decision carries:
/// the decision, the highest matching specificity, whether an ALLOW
/// existed at that specificity, whether a DENY existed at that
/// specificity, and a coarse DENY reason.
///
/// Only the documented coherent states can be constructed (via the
/// constructors below):
///
/// ```text
/// NO MATCH:      DENY, specificity=None, allow=false, deny=false, reason=NO_MATCH
/// MATCHED DENY:  DENY, specificity=EXACT|WILDCARD, deny=true, reason=MATCHED_DENY
///                (allow=true only when an equal-specificity ALLOW also matched)
/// MATCHED ALLOW: ALLOW, specificity=EXACT|WILDCARD, allow=true, deny=false, reason=None
/// ```
///
/// The constructors make it impossible to emit an incoherent state such
/// as ALLOW with a deny reason, ALLOW with `matched_deny=true`, or a
/// NO_MATCH carrying a specificity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationResult {
    pub decision: EvaluationDecision,
    pub matched_specificity: Option<MatchSpecificity>,
    pub matched_allow: bool,
    pub matched_deny: bool,
    pub deny_reason: Option<DenyReason>,
}

impl EvaluationResult {
    /// Construct the NO_MATCH state: DENY with no matching evidence.
    pub fn no_match() -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            matched_specificity: None,
            matched_allow: false,
            matched_deny: false,
            deny_reason: Some(DenyReason::NoMatch),
        }
    }

    /// Construct the MATCHED_DENY state: DENY because a DENY matched at
    /// the maximum specificity.
    ///
    /// `matched_allow` reports whether an equal-specificity ALLOW also
    /// matched (the DENY still wins).
    pub fn matched_deny(specificity: MatchSpecificity, matched_allow: bool) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            matched_specificity: Some(specificity),
            matched_allow,
            matched_deny: true,
            deny_reason: Some(DenyReason::MatchedDeny),
        }
    }

    /// Construct the MATCHED_ALLOW state: ALLOW because an ALLOW matched
    /// at the maximum specificity and no equal-specificity DENY did.
    pub fn allow(specificity: MatchSpecificity) -> Self {
        Self {
            decision: EvaluationDecision::Allow,
            matched_specificity: Some(specificity),
            matched_allow: true,
            matched_deny: false,
            deny_reason: None,
        }
    }
}

/// Already-parsed detached policy set consumed by the canonical core.
///
/// This is the single shared representation between the production URN
/// input path (which parses once and then evaluates) and the
/// experimental semantic-buffer path (which validates wire components
/// and constructs these shapes directly, without ever parsing a
/// complete URN). Both paths converge on [`evaluate_parsed`]: there is
/// exactly one canonical decision loop in the crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedPolicySet {
    pub effect: PermissionEffect,
    pub permissions: Vec<ParsedPermissionUrn>,
}

/// Evaluate one exact Action against zero or more already-applicable
/// PermissionSets.
///
/// The Action is parsed once per evaluation. Each Permission is parsed
/// as needed before it is matched with the canonical matcher.
///
/// - Malformed Action or Permission URNs fail the whole evaluation with
///   a [`UrnParseError`]; they are never converted into `DENY / NO_MATCH`
///   or any other decision.
/// - Valid but empty or non-matching policy yields `DENY / NO_MATCH`.
/// - The result is deterministic and independent of PermissionSet order,
///   Permission order, and duplicate positions.
pub fn evaluate(
    action: &ActionInput,
    permission_sets: &[PermissionSetInput],
) -> Result<EvaluationResult, UrnParseError> {
    let parsed_action = parse_action_urn(&action.action_urn)?;
    let mut parsed_sets = Vec::with_capacity(permission_sets.len());
    for permission_set in permission_sets {
        let mut parsed_permissions = Vec::with_capacity(permission_set.permissions.len());
        for permission in &permission_set.permissions {
            parsed_permissions.push(parse_permission_urn(&permission.permission_urn)?);
        }
        parsed_sets.push(ParsedPolicySet {
            effect: permission_set.effect,
            permissions: parsed_permissions,
        });
    }
    Ok(evaluate_parsed(&parsed_action, &parsed_sets))
}

/// The canonical decision loop over an already-parsed Action and
/// already-parsed detached PermissionSets.
///
/// This is the single semantic decision implementation in the crate.
/// The production URN path and the experimental semantic-buffer path
/// both converge here, so no path can implement an independent
/// authorization algorithm: exact matching, complete-qualifier wildcard
/// matching, specificity ordering, maximum-specificity selection,
/// lower-specificity discard, equal-specificity DENY precedence,
/// default DENY, and result evidence are defined exactly once.
///
/// Evaluation remains synchronous, deterministic, side-effect-free,
/// I/O-free, cache-free, and free of global mutable policy state, and
/// independent of PermissionSet order, Permission order, and duplicate
/// positions.
pub(crate) fn evaluate_parsed(
    parsed_action: &ParsedActionUrn,
    parsed_sets: &[ParsedPolicySet],
) -> EvaluationResult {
    let mut highest: Option<MatchSpecificity> = None;
    let mut matched_allow = false;
    let mut matched_deny = false;
    for parsed_set in parsed_sets {
        for parsed_permission in &parsed_set.permissions {
            match match_permission(parsed_permission, parsed_action) {
                MatchResult::NoMatch => {}
                MatchResult::Match(specificity) => match highest {
                    None => {
                        highest = Some(specificity);
                        matched_allow = parsed_set.effect == PermissionEffect::Allow;
                        matched_deny = parsed_set.effect == PermissionEffect::Deny;
                    }
                    // A strictly higher specificity resets the
                    // accumulated effect evidence: lower-specificity
                    // matches must not remain in the final result.
                    Some(current) if specificity.is_more_specific_than(current) => {
                        highest = Some(specificity);
                        matched_allow = parsed_set.effect == PermissionEffect::Allow;
                        matched_deny = parsed_set.effect == PermissionEffect::Deny;
                    }
                    // Equal specificity accumulates effect evidence.
                    Some(current) if specificity == current => {
                        matched_allow =
                            matched_allow || parsed_set.effect == PermissionEffect::Allow;
                        matched_deny = matched_deny || parsed_set.effect == PermissionEffect::Deny;
                    }
                    // Lower specificity: ignored.
                    Some(_) => {}
                },
            }
        }
    }
    match highest {
        None => EvaluationResult::no_match(),
        // At maximum specificity a DENY wins over any equal ALLOW.
        Some(specificity) if matched_deny => {
            EvaluationResult::matched_deny(specificity, matched_allow)
        }
        // No DENY at maximum specificity: an ALLOW matched there, since
        // every match carries exactly one of the two effects. The
        // two-variant effect enum makes the `matched_allow` flag true by
        // construction whenever this arm is reached.
        Some(specificity) => EvaluationResult::allow(specificity),
    }
}

#[cfg(test)]
mod tests {
    use crate::evaluator::{DenyReason, EvaluationDecision, EvaluationResult, evaluate};
    use crate::matcher::MatchSpecificity;
    use crate::model::{ActionInput, PermissionEffect, PermissionInput, PermissionSetInput};
    use crate::urn::UrnParseError;

    // Canonical URN texts used across the matrix.
    const ACTION_SET_ACTIVE: &str = "urn:mtmf:iam:actions:system:principal:set-active";
    const ACTION_SET_ALIAS: &str = "urn:mtmf:iam:actions:system:principal:set-alias";
    const PERM_SET_ACTIVE: &str = "urn:mtmf:iam:permissions:system:principal:set-active";
    const PERM_SET_ALIAS: &str = "urn:mtmf:iam:permissions:system:principal:set-alias";
    const PERM_SET_ANY: &str = "urn:mtmf:iam:permissions:system:principal:set-*";
    const PERM_GET_OBJECT: &str = "urn:mtmf:iam:permissions:system:principal:get-object";
    const PERM_TENANT_SET_ANY: &str = "urn:mtmf:iam:permissions:system:tenant:set-*";

    fn action(value: &str) -> ActionInput {
        ActionInput {
            action_urn: value.to_string(),
        }
    }

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

    fn eval_set(sets: Vec<PermissionSetInput>) -> EvaluationResult {
        evaluate(&action(ACTION_SET_ACTIVE), &sets).unwrap()
    }

    // Convenience result constructors so expectations read as policies.
    fn expect_allow(specificity: MatchSpecificity) -> EvaluationResult {
        EvaluationResult::allow(specificity)
    }

    fn expect_no_match() -> EvaluationResult {
        EvaluationResult::no_match()
    }

    fn expect_matched_deny(specificity: MatchSpecificity, matched_allow: bool) -> EvaluationResult {
        EvaluationResult::matched_deny(specificity, matched_allow)
    }

    // --- Default deny ----------------------------------------------------

    #[test]
    fn zero_permission_sets_is_default_deny() {
        assert_eq!(eval_set(Vec::new()), expect_no_match());
    }

    #[test]
    fn one_empty_set_is_default_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([allow_set(Vec::new())])),
            expect_no_match()
        );
    }

    #[test]
    fn multiple_empty_sets_are_default_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::new()),
                deny_set(Vec::new()),
                allow_set(Vec::new()),
            ])),
            expect_no_match(),
        );
    }

    #[test]
    fn nonmatching_permissions_are_default_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_GET_OBJECT)])),
                deny_set(Vec::from_iter([perm(PERM_TENANT_SET_ANY)])),
            ])),
            expect_no_match(),
        );
    }

    // --- Single matches ---------------------------------------------------

    #[test]
    fn single_exact_allow() {
        assert_eq!(
            eval_set(Vec::from_iter([allow_set(Vec::from_iter([perm(
                PERM_SET_ACTIVE
            )]))])),
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn single_exact_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([deny_set(Vec::from_iter([perm(
                PERM_SET_ACTIVE
            )]))])),
            expect_matched_deny(MatchSpecificity::Exact, false),
        );
    }

    #[test]
    fn single_wildcard_allow() {
        assert_eq!(
            eval_set(Vec::from_iter([allow_set(Vec::from_iter([perm(
                PERM_SET_ANY
            )]))])),
            expect_allow(MatchSpecificity::QualifierWildcard),
        );
    }

    #[test]
    fn single_wildcard_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([deny_set(Vec::from_iter([perm(
                PERM_SET_ANY
            )]))])),
            expect_matched_deny(MatchSpecificity::QualifierWildcard, false),
        );
    }

    // --- Specificity: lower specificity is discarded before effects ------

    #[test]
    fn wildcard_allow_plus_exact_deny_is_exact_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            // The wildcard ALLOW must not survive into the final
            // evidence: matched_allow stays false.
            expect_matched_deny(MatchSpecificity::Exact, false),
        );
    }

    #[test]
    fn wildcard_deny_plus_exact_allow_is_exact_allow() {
        assert_eq!(
            eval_set(Vec::from_iter([
                deny_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            // The wildcard DENY must not survive into the final
            // evidence: matched_deny stays false.
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn wildcard_allow_plus_exact_allow_is_exact_allow() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn wildcard_deny_plus_exact_deny_is_exact_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([
                deny_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_matched_deny(MatchSpecificity::Exact, false),
        );
    }

    // --- Equal specificity ------------------------------------------------

    #[test]
    fn equal_exact_allow_and_deny_is_deny_with_both_flag_evidence() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_matched_deny(MatchSpecificity::Exact, true),
        );
    }

    #[test]
    fn equal_wildcard_allow_and_deny_is_deny_with_both_flag_evidence() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ANY)])),
            ])),
            expect_matched_deny(MatchSpecificity::QualifierWildcard, true),
        );
    }

    // --- Duplicates create no voting semantics ----------------------------

    #[test]
    fn duplicate_exact_allow_is_still_allow() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn duplicate_exact_deny_is_still_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([
                deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_matched_deny(MatchSpecificity::Exact, false),
        );
    }

    #[test]
    fn duplicate_wildcard_allow_is_still_allow() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ANY)])),
            ])),
            expect_allow(MatchSpecificity::QualifierWildcard),
        );
    }

    #[test]
    fn duplicate_wildcard_deny_is_still_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([
                deny_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ANY)])),
            ])),
            expect_matched_deny(MatchSpecificity::QualifierWildcard, false),
        );
    }

    #[test]
    fn duplicate_allow_does_not_outweigh_equal_deny() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_matched_deny(MatchSpecificity::Exact, true),
        );
    }

    // --- Multiple structures ----------------------------------------------

    #[test]
    fn several_nonmatches_plus_one_match() {
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([
                    perm(PERM_GET_OBJECT),
                    perm(PERM_TENANT_SET_ANY)
                ])),
                deny_set(Vec::from_iter([perm(PERM_TENANT_SET_ANY)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn several_sets_with_different_specificity() {
        // A NoMatch set, a wildcard DENY set, a wildcard ALLOW set, and
        // an exact ALLOW set: only the exact ALLOW survives.
        assert_eq!(
            eval_set(Vec::from_iter([
                allow_set(Vec::from_iter([perm(PERM_GET_OBJECT)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ANY)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_allow(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn several_sets_with_equal_specificity_conflict() {
        assert_eq!(
            eval_set(Vec::from_iter([
                deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
                allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
                deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            ])),
            expect_matched_deny(MatchSpecificity::Exact, true),
        );
    }

    #[test]
    fn one_set_with_matching_and_nonmatching_permissions() {
        assert_eq!(
            eval_set(Vec::from_iter([allow_set(Vec::from_iter([
                perm(PERM_GET_OBJECT),
                perm(PERM_SET_ACTIVE)
            ])),])),
            expect_allow(MatchSpecificity::Exact),
        );
    }

    // --- Matching behavior (reuses the canonical matcher) ------------------

    #[test]
    fn resource_mismatch_is_no_match() {
        assert_eq!(
            eval_set(Vec::from_iter([allow_set(Vec::from_iter([perm(
                PERM_TENANT_SET_ANY
            )]))])),
            expect_no_match(),
        );
    }

    #[test]
    fn verb_mismatch_is_no_match() {
        assert_eq!(
            eval_set(Vec::from_iter([allow_set(Vec::from_iter([perm(
                PERM_GET_OBJECT
            )]))])),
            expect_no_match(),
        );
    }

    #[test]
    fn exact_qualifier_mismatch_is_no_match() {
        assert_eq!(
            eval_set(Vec::from_iter([allow_set(Vec::from_iter([perm(
                PERM_SET_ALIAS
            )]))])),
            expect_no_match(),
        );
    }

    #[test]
    fn wildcard_qualifier_matches_other_qualifiers() {
        let result = evaluate(
            &action(ACTION_SET_ALIAS),
            &[allow_set(Vec::from_iter([perm(PERM_SET_ANY)]))],
        )
        .unwrap();
        assert_eq!(result, expect_allow(MatchSpecificity::QualifierWildcard));
    }

    #[test]
    fn later_hyphen_exact_qualifier_matches_exactly() {
        let self_hosted = perm("urn:mtmf:iam:permissions:system:principal:set-self-hosted");
        let result = evaluate(
            &action("urn:mtmf:iam:actions:system:principal:set-self-hosted"),
            &[allow_set(Vec::from_iter([self_hosted]))],
        )
        .unwrap();
        assert_eq!(result, expect_allow(MatchSpecificity::Exact));
    }

    // --- Invalid input fails explicitly, never as DENY --------------------

    #[test]
    fn malformed_action_fails_evaluation() {
        assert!(
            evaluate(
                &action("not-a-urn"),
                &[allow_set(Vec::from_iter([perm(PERM_SET_ANY)]))],
            )
            .is_err()
        );
    }

    #[test]
    fn wildcard_action_fails_evaluation() {
        // Actions are exact only: a wildcard Action is malformed input,
        // not a policy DENY.
        assert!(
            evaluate(
                &action("urn:mtmf:iam:actions:system:principal:set-*"),
                &[allow_set(Vec::from_iter([perm(PERM_SET_ANY)]))],
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_permission_fails_evaluation() {
        assert!(
            evaluate(
                &action(ACTION_SET_ACTIVE),
                &[allow_set(Vec::from_iter([PermissionInput {
                    permission_urn: "not-a-urn".to_string(),
                }]))],
            )
            .is_err()
        );
    }

    #[test]
    fn unsupported_namespace_fails_evaluation() {
        assert!(
            evaluate(
                &action(ACTION_SET_ACTIVE),
                &[allow_set(Vec::from_iter([perm(
                    "urn:mtmf:iam:permissions:tenant:principal:set-active",
                )]))],
            )
            .is_err()
        );
    }

    #[test]
    fn partial_wildcard_permission_fails_evaluation() {
        assert!(
            evaluate(
                &action(ACTION_SET_ACTIVE),
                &[allow_set(Vec::from_iter([perm(
                    "urn:mtmf:iam:permissions:system:principal:set-act*ve",
                )]))],
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_input_never_becomes_no_match() {
        // Even a single malformed Permission, alongside otherwise valid
        // non-matching policy, fails the evaluation instead of yielding
        // DENY/NO_MATCH or any other decision.
        let outcome = evaluate(
            &action(ACTION_SET_ACTIVE),
            &[
                deny_set(Vec::from_iter([perm(PERM_GET_OBJECT)])),
                allow_set(Vec::from_iter([PermissionInput {
                    permission_urn: "".to_string(),
                }])),
            ],
        );
        assert!(outcome.is_err());
    }

    #[test]
    fn malformed_action_fails_even_with_no_permission_sets() {
        assert!(evaluate(&action("urn:mtmf:iam:actions:"), &[]).is_err());
    }

    #[test]
    fn error_kind_is_a_urn_parse_error() {
        // The evaluator has exactly one failure channel: `UrnParseError`
        // from the reused parsers. "not-a-urn" is rejected by the
        // prefix check with the classified kind - never a decision.
        let outcome: Result<EvaluationResult, UrnParseError> = evaluate(
            &action(ACTION_SET_ACTIVE),
            &[allow_set(Vec::from_iter([perm("not-a-urn")]))],
        );
        assert_eq!(outcome, Err(UrnParseError::InvalidPrefix));
    }

    // --- Determinism and order independence --------------------------------

    #[test]
    fn repeated_evaluation_is_identical() {
        let sets: Vec<PermissionSetInput> = Vec::from_iter([
            deny_set(Vec::from_iter([perm(PERM_SET_ANY)])),
            allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
        ]);
        let first = evaluate(&action(ACTION_SET_ACTIVE), &sets).unwrap();
        for _ in 0..5 {
            assert_eq!(evaluate(&action(ACTION_SET_ACTIVE), &sets).unwrap(), first);
        }
    }

    #[test]
    fn reversed_permission_set_order_is_identical() {
        let forward: Vec<PermissionSetInput> = Vec::from_iter([
            allow_set(Vec::from_iter([perm(PERM_SET_ANY)])),
            deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
        ]);
        let reversed: Vec<PermissionSetInput> = Vec::from_iter([
            deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)])),
            allow_set(Vec::from_iter([perm(PERM_SET_ANY)])),
        ]);
        assert_eq!(
            evaluate(&action(ACTION_SET_ACTIVE), &forward).unwrap(),
            evaluate(&action(ACTION_SET_ACTIVE), &reversed).unwrap(),
        );
    }

    #[test]
    fn all_three_set_permutations_are_identical() {
        // Set one: wildcard ALLOW; set two: exact DENY; set three:
        // non-matching ALLOW. Every permutation must produce the exact
        // DENY with no whiff of the wildcard ALLOW.
        let one = allow_set(Vec::from_iter([perm(PERM_SET_ANY)]));
        let two = deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)]));
        let three = allow_set(Vec::from_iter([perm(PERM_GET_OBJECT)]));
        let expected = expect_matched_deny(MatchSpecificity::Exact, false);
        let permutations: Vec<Vec<PermissionSetInput>> = Vec::from_iter([
            Vec::from_iter([one.clone(), two.clone(), three.clone()]),
            Vec::from_iter([one.clone(), three.clone(), two.clone()]),
            Vec::from_iter([two.clone(), one.clone(), three.clone()]),
            Vec::from_iter([two.clone(), three.clone(), one.clone()]),
            Vec::from_iter([three.clone(), one.clone(), two.clone()]),
            Vec::from_iter([three.clone(), two.clone(), one.clone()]),
        ]);
        for (index, pick) in permutations.into_iter().enumerate() {
            let message = format!("permutation {index} must be identical");
            assert_eq!(
                evaluate(&action(ACTION_SET_ACTIVE), &pick).unwrap(),
                expected,
                "{message}",
            );
        }
    }

    #[test]
    fn reversed_permission_order_inside_a_set_is_identical() {
        let one_order = allow_set(Vec::from_iter([
            perm(PERM_GET_OBJECT),
            perm(PERM_SET_ANY),
            perm(PERM_SET_ACTIVE),
        ]));
        let other_order = allow_set(Vec::from_iter([
            perm(PERM_SET_ACTIVE),
            perm(PERM_SET_ANY),
            perm(PERM_GET_OBJECT),
        ]));
        assert_eq!(
            evaluate(&action(ACTION_SET_ACTIVE), &[one_order]).unwrap(),
            evaluate(&action(ACTION_SET_ACTIVE), &[other_order]).unwrap(),
        );
    }

    #[test]
    fn changed_duplicate_positions_are_identical() {
        // The same duplicate ALLOW set occupies different positions
        // around an exact DENY; the result stays the same.
        let dupe_a = allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)]));
        let dupe_b = allow_set(Vec::from_iter([perm(PERM_SET_ACTIVE)]));
        let denier = deny_set(Vec::from_iter([perm(PERM_SET_ACTIVE)]));
        let expected = expect_matched_deny(MatchSpecificity::Exact, true);
        assert_eq!(
            evaluate(
                &action(ACTION_SET_ACTIVE),
                &[dupe_a.clone(), denier.clone(), dupe_b.clone()],
            )
            .unwrap(),
            expected,
        );
        assert_eq!(
            evaluate(
                &action(ACTION_SET_ACTIVE),
                &[denier.clone(), dupe_a.clone(), dupe_b.clone()],
            )
            .unwrap(),
            expected,
        );
    }

    // --- Coherent result states --------------------------------------------

    #[test]
    fn no_match_state_carries_no_specificity_or_flags() {
        let result = expect_no_match();
        assert_eq!(result.decision, EvaluationDecision::Deny);
        assert_eq!(result.matched_specificity, None);
        assert!(!result.matched_allow);
        assert!(!result.matched_deny);
        assert_eq!(result.deny_reason, Some(DenyReason::NoMatch));
    }

    #[test]
    fn allow_state_carries_no_deny_reason() {
        let result = eval_set(Vec::from_iter([allow_set(Vec::from_iter([perm(
            PERM_SET_ACTIVE,
        )]))]));
        assert_eq!(result.decision, EvaluationDecision::Allow);
        assert_eq!(result.matched_specificity, Some(MatchSpecificity::Exact));
        assert!(result.matched_allow);
        assert!(!result.matched_deny);
        assert_eq!(result.deny_reason, None);
    }

    #[test]
    fn matched_deny_state_is_distinguishable_from_no_match() {
        let no_match = expect_no_match();
        let matched = expect_matched_deny(MatchSpecificity::Exact, false);
        assert_ne!(
            (no_match.decision, no_match.deny_reason),
            (matched.decision, matched.deny_reason),
        );
        assert_eq!(no_match.deny_reason, Some(DenyReason::NoMatch));
        assert_eq!(matched.deny_reason, Some(DenyReason::MatchedDeny));
    }
}
