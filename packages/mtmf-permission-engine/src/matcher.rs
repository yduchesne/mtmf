//! Single-Permission matching and specificity (PR 8B).
//!
//! Port of the Python reference (`mtmf_core.domain.permission_matching`)
//! for one Permission matcher URN against one exact Action URN. A match
//! fact carries no effect and no decision: it answers only whether and
//! with which specificity the Permission matches the Action.
//!
//! There are exactly two specificity classes, and exactly one ordering
//! is true: EXACT is more specific than QUALIFIER_WILDCARD. Enum
//! declaration order is never used as policy semantics.

use crate::model::{ActionInput, PermissionInput};
use crate::urn::{ParsedActionUrn, ParsedPermissionUrn};

/// The two matching-specificity classes defined by the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchSpecificity {
    QualifierWildcard,
    Exact,
}

impl MatchSpecificity {
    /// Return whether this specificity is strictly more specific than
    /// `other`.
    ///
    /// The model defines exactly one documented ordering: EXACT is more
    /// specific than QUALIFIER_WILDCARD. No value is more specific than
    /// itself. PR 8B does not select among specificities (that is PR 8C
    /// evaluation work), so this contract method is exercised by the
    /// native specificity tests only; it is declared explicitly rather
    /// than relying on enum declaration order.
    #[allow(dead_code)]
    pub fn is_more_specific_than(self, other: Self) -> bool {
        matches!((self, other), (Self::Exact, Self::QualifierWildcard))
    }
}

/// The deterministic result of matching one Permission against one
/// Action.
///
/// [`MatchResult::NoMatch`] is a valid non-match. A match carries a
/// specificity only; it never carries an effect, a PermissionSet
/// resolution, or an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchResult {
    NoMatch,
    Match(MatchSpecificity),
}

/// Match one parsed Permission matcher against one parsed exact Action.
///
/// The comparison covers the security-relevant parsed fields in the
/// documented order: definition namespace, resource, verb, and
/// qualifier. A complete-qualifier wildcard matches any exact qualifier
/// of the same resource and verb; anything else must match exactly.
/// The PermissionSet effect is never consulted here.
pub fn match_permission(permission: &ParsedPermissionUrn, action: &ParsedActionUrn) -> MatchResult {
    if permission.namespace != action.namespace {
        return MatchResult::NoMatch;
    }
    if permission.resource != action.resource {
        return MatchResult::NoMatch;
    }
    if permission.verb != action.verb {
        return MatchResult::NoMatch;
    }
    if permission.is_wildcard() {
        return MatchResult::Match(MatchSpecificity::QualifierWildcard);
    }
    if permission.qualifier == action.qualifier {
        return MatchResult::Match(MatchSpecificity::Exact);
    }
    MatchResult::NoMatch
}

/// Match a Permission URN against an Action URN, parsing both.
///
/// Malformed input is a parsing failure (`Err`), never a valid
/// `NoMatch`. Valid but non-matching input yields
/// [`MatchResult::NoMatch`]. This distinction is what keeps malformed
/// input from becoming a silent DENY or ALLOW on any future evaluation
/// path.
pub fn match_permission_urns(
    action_urn: &str,
    permission_urn: &str,
) -> Result<MatchResult, crate::urn::UrnParseError> {
    let action = ActionInput {
        action_urn: action_urn.to_string(),
    };
    let permission = PermissionInput {
        permission_urn: permission_urn.to_string(),
    };
    match_detached_inputs(&action, &permission)
}

/// Parse and match one detached Action input against one detached
/// Permission input.
///
/// This is the detached-input matcher shape the PR 8C evaluator will
/// consume: primitive detached inputs in, a single-Permission match fact
/// out. Parsing failures are `Err` (`ValueError` at the Python
/// boundary), never a valid non-match.
pub fn match_detached_inputs(
    action: &ActionInput,
    permission: &PermissionInput,
) -> Result<MatchResult, crate::urn::UrnParseError> {
    let parsed_action = crate::urn::parse_action_urn(&action.action_urn)?;
    let parsed_permission = crate::urn::parse_permission_urn(&permission.permission_urn)?;
    Ok(match_permission(&parsed_permission, &parsed_action))
}

#[cfg(test)]
mod tests {
    use crate::matcher::{MatchResult, MatchSpecificity, match_detached_inputs, match_permission};
    use crate::model::{ActionInput, PermissionInput};
    use crate::urn::{WILDCARD, parse_action_urn, parse_permission_urn};

    fn action(value: &str) -> crate::urn::ParsedActionUrn {
        parse_action_urn(value).unwrap()
    }

    fn permission(value: &str) -> crate::urn::ParsedPermissionUrn {
        parse_permission_urn(value).unwrap()
    }

    #[test]
    fn exact_match_is_exact() {
        let result = match_permission(
            &permission("urn:mtmf:iam:permissions:system:principal:set-active"),
            &action("urn:mtmf:iam:actions:system:principal:set-active"),
        );
        assert_eq!(result, MatchResult::Match(MatchSpecificity::Exact));
    }

    #[test]
    fn namespace_is_always_equal_for_parsed_system_urns() {
        // Only `system` parses, so the namespace comparison is vacuously
        // equal for every valid pair; the check stays for parity with
        // the Python reference.
        let wildcard = permission("urn:mtmf:iam:permissions:system:principal:set-*");
        let set_active = action("urn:mtmf:iam:actions:system:principal:set-active");
        assert_eq!(wildcard.namespace, set_active.namespace);
        assert_eq!(wildcard.namespace, "system");
        let result = match_permission(&wildcard, &set_active);
        assert_eq!(
            result,
            MatchResult::Match(MatchSpecificity::QualifierWildcard)
        );
    }

    #[test]
    fn wildcard_match_is_qualifier_wildcard() {
        let result = match_permission(
            &permission("urn:mtmf:iam:permissions:system:principal:set-*"),
            &action("urn:mtmf:iam:actions:system:principal:set-active"),
        );
        assert_eq!(
            result,
            MatchResult::Match(MatchSpecificity::QualifierWildcard)
        );
    }

    #[test]
    fn wildcard_matches_any_qualifier_of_same_verb() {
        let wildcard = permission("urn:mtmf:iam:permissions:system:principal:set-*");
        let set_active = action("urn:mtmf:iam:actions:system:principal:set-active");
        let set_alias = action("urn:mtmf:iam:actions:system:principal:set-alias");
        assert_eq!(
            match_permission(&wildcard, &set_active),
            MatchResult::Match(MatchSpecificity::QualifierWildcard),
        );
        assert_eq!(
            match_permission(&wildcard, &set_alias),
            MatchResult::Match(MatchSpecificity::QualifierWildcard),
        );
    }

    #[test]
    fn qualifier_mismatch_does_not_match() {
        let exact = permission("urn:mtmf:iam:permissions:system:principal:set-active");
        let set_inactive = action("urn:mtmf:iam:actions:system:principal:set-inactive");
        assert_eq!(
            match_permission(&exact, &set_inactive),
            MatchResult::NoMatch
        );
    }

    #[test]
    fn resource_mismatch_does_not_match() {
        let wildcard = permission("urn:mtmf:iam:permissions:system:principal:set-*");
        let tenant_set = action("urn:mtmf:iam:actions:system:tenant:set-active");
        assert_eq!(
            match_permission(&wildcard, &tenant_set),
            MatchResult::NoMatch
        );
    }

    #[test]
    fn verb_mismatch_does_not_match() {
        let wildcard = permission("urn:mtmf:iam:permissions:system:principal:set-*");
        let get_object = action("urn:mtmf:iam:actions:system:principal:get-object");
        assert_eq!(
            match_permission(&wildcard, &get_object),
            MatchResult::NoMatch
        );
    }

    #[test]
    fn later_hyphen_exact_matches() {
        let same = permission("urn:mtmf:iam:permissions:system:principal:set-self-hosted");
        let same_action = action("urn:mtmf:iam:actions:system:principal:set-self-hosted");
        assert_eq!(
            match_permission(&same, &same_action),
            MatchResult::Match(MatchSpecificity::Exact),
        );
    }

    #[test]
    fn later_hyphen_mismatch_does_not_match() {
        let one = permission("urn:mtmf:iam:permissions:system:principal:set-self-hosted");
        let other = action("urn:mtmf:iam:actions:system:principal:set-self-hosted-v2");
        assert_eq!(match_permission(&one, &other), MatchResult::NoMatch);
    }

    #[test]
    fn repeated_input_yields_identical_result() {
        let wildcard = permission("urn:mtmf:iam:permissions:system:principal:set-*");
        let action = action("urn:mtmf:iam:actions:system:principal:set-active");
        let first = match_permission(&wildcard, &action);
        let second = match_permission(&wildcard, &action);
        assert_eq!(first, second);
    }

    #[test]
    fn detached_input_matcher_agrees_with_string_matcher() {
        let action_input = ActionInput {
            action_urn: "urn:mtmf:iam:actions:system:principal:set-active".to_string(),
        };
        let exact = PermissionInput {
            permission_urn: "urn:mtmf:iam:permissions:system:principal:set-active".to_string(),
        };
        let wildcard = PermissionInput {
            permission_urn: "urn:mtmf:iam:permissions:system:principal:set-*".to_string(),
        };
        assert_eq!(
            match_detached_inputs(&action_input, &exact).unwrap(),
            MatchResult::Match(MatchSpecificity::Exact),
        );
        assert_eq!(
            match_detached_inputs(&action_input, &wildcard).unwrap(),
            MatchResult::Match(MatchSpecificity::QualifierWildcard),
        );
        // Malformed detached input is a parsing failure, never a valid
        // non-match.
        let malformed = PermissionInput {
            permission_urn: "not-a-urn".to_string(),
        };
        assert!(match_detached_inputs(&action_input, &malformed).is_err());
    }

    #[test]
    fn match_result_has_exactly_two_specificity_classes() {
        assert_ne!(MatchSpecificity::Exact, MatchSpecificity::QualifierWildcard);
    }

    #[test]
    fn specificity_ordering_is_exactly_exact_over_wildcard() {
        assert!(MatchSpecificity::Exact.is_more_specific_than(MatchSpecificity::QualifierWildcard));
        assert!(
            !MatchSpecificity::QualifierWildcard.is_more_specific_than(MatchSpecificity::Exact)
        );
        assert!(!MatchSpecificity::Exact.is_more_specific_than(MatchSpecificity::Exact));
        assert!(
            !MatchSpecificity::QualifierWildcard
                .is_more_specific_than(MatchSpecificity::QualifierWildcard,)
        );
    }

    #[test]
    fn wildcard_constant_equals_wildcard_qualifier() {
        assert_eq!(WILDCARD, "*");
    }
}
