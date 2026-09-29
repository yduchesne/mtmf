//! Experimental msgspec/MessagePack semantic-buffer boundary (PR 8F).
//!
//! This module is the Rust half of a deliberately isolated performance
//! experiment: it decodes one versioned *positional* MessagePack
//! payload whose Action/Permission data are already-parsed semantic
//! components (definition namespace, resource, verb, qualifier, and an
//! explicit wildcard flag) - **never complete MTMF Action/Permission
//! URN texts** - so the canonical decision loop is reached without any
//! URN reparsing.
//!
//! The module adds NO authorization semantics. It:
//!
//! - decodes the payload with `rmp-serde`/`serde` into detached wire
//!   shapes;
//! - rejects unsupported wire versions explicitly;
//! - validates every component against exactly the states the canonical
//!   SYSTEM grammar accepts (supported namespace, non-empty
//!   resource/verb, exact Action qualifier with no Action wildcard,
//!   structurally valid Permission wildcard, exact Permission
//!   qualifier, exact ALLOW/DENY effect representation);
//! - maps the validated components onto the canonical parsed shapes
//!   ([`ParsedActionUrn`] / [`ParsedPermissionUrn`]);
//! - delegates to the canonical core evaluator
//!   ([`evaluate_parsed`]) - the same single decision loop the
//!   production URN path uses. There is no second authorization
//!   algorithm and no fast-path semantics.
//!
//! The module stays detached, private, I/O-free, context-free,
//! persistence-free, and free of caching/compiled-policy state, and it
//! carries no Role identity. Malformed wire input (empty/truncated
//! payloads, random bytes, a valid MessagePack document of the wrong
//! top-level type, wrong field types, missing fields, unsupported
//! versions, unknown effects, invalid namespaces, empty/whitespace
//! components, Action wildcards, inconsistent/invalid wildcard state,
//! and reasonably bounded excessive nesting) fails with
//! [`SemanticError`] and can never become `ALLOW`, `NO_MATCH`, or
//! `MATCHED_DENY`.

use serde::Deserialize;

use crate::evaluator::{EvaluationResult, ParsedPolicySet, evaluate_parsed};
use crate::model::PermissionEffect;
use crate::urn::{ParsedActionUrn, ParsedPermissionUrn, SYSTEM_NAMESPACE, WILDCARD};

/// The only wire schema version this boundary understands.
///
/// Version failures are explicit and versioned compatibility logic for
/// nonexistent versions is deliberately not implemented: any other
/// value is [`SemanticError::UnsupportedVersion`].
pub const WIRE_VERSION: u32 = 1;

// --- Positional wire shapes (mirror the msgspec array-like DTOs) ---
//
// The `serde`-derived decoders read MessagePack arrays positionally in
// field-declaration order, exactly matching the msgspec
// `array_like=True` encoding. Field-name maps are never encoded.

/// Positional Action wire shape: semantic components, no URN text.
#[derive(Debug, Deserialize)]
struct WireAction {
    namespace: String,
    resource: String,
    verb: String,
    qualifier: String,
}

/// Positional Permission wire shape: semantic components plus an
/// explicit complete-qualifier wildcard flag.
#[derive(Debug, Deserialize)]
struct WirePermission {
    namespace: String,
    resource: String,
    verb: String,
    qualifier: String,
    qualifier_wildcard: bool,
}

/// Positional PermissionSet wire shape: exact effect text plus owned
/// Permissions.
#[derive(Debug, Deserialize)]
struct WirePermissionSet {
    effect: String,
    permissions: Vec<WirePermission>,
}

/// Top-level positional payload: `[version, action, permission_sets]`.
#[derive(Debug, Deserialize)]
struct WireEvaluationPayload {
    version: u32,
    action: WireAction,
    permission_sets: Vec<WirePermissionSet>,
}

// --- Detached semantic-input model (PR 8F section 11) ---
//
// A separate private semantic-input model, distinct from the existing
// URN-text input model (`model.rs`). These shapes are what the
// experimental path validates and evaluates; they are kept apart so the
// production URN-text input model is untouched.

/// Detached already-parsed Action semantic input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticActionInput {
    pub namespace: String,
    pub resource: String,
    pub verb: String,
    pub qualifier: String,
}

/// Detached already-parsed Permission semantic input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPermissionInput {
    pub namespace: String,
    pub resource: String,
    pub verb: String,
    pub qualifier: String,
    pub qualifier_wildcard: bool,
}

/// Detached PermissionSet semantic input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPermissionSetInput {
    pub effect: PermissionEffect,
    pub permissions: Vec<SemanticPermissionInput>,
}

/// Wire/semantic validation failure classification.
///
/// Every variant is an infrastructure/formatting failure, never a
/// policy decision. Malformed wire input cannot become ALLOW,
/// NO_MATCH, or MATCHED_DENY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticError {
    /// The payload is not a decodable MessagePack document of the
    /// expected positional shape (empty/truncated, random bytes, wrong
    /// top-level type, wrong field types, missing fields).
    MalformedPayload,
    /// The payload's version marker is not exactly [`WIRE_VERSION`].
    UnsupportedVersion,
    /// A component namespace is not exactly `system`.
    InvalidNamespace,
    /// A component is empty.
    EmptyComponent,
    /// A component contains whitespace.
    Whitespace,
    /// A PermissionSet effect is not exactly `allow` or `deny`.
    InvalidEffect,
    /// A Permission wildcard state/placement violates the grammar
    /// (wildcard in resource/verb, a non-complete qualifier wildcard,
    /// or a mismatch between `qualifier_wildcard` and the qualifier
    /// text).
    InvalidWildcard,
    /// An Action component contains a wildcard (Actions are exact
    /// only).
    ActionWildcard,
}

impl SemanticError {
    /// A stable human-readable description of the failure.
    pub fn describe(self) -> &'static str {
        match self {
            Self::MalformedPayload => "payload is not a valid v1 semantic MessagePack document",
            Self::UnsupportedVersion => "unsupported semantic wire version; expected exactly 1",
            Self::InvalidNamespace => {
                "semantic components must use the 'system' definition namespace"
            }
            Self::EmptyComponent => "semantic components must not be empty",
            Self::Whitespace => "semantic components must not contain whitespace",
            Self::InvalidEffect => "PermissionSet effect must be exactly 'allow' or 'deny'",
            Self::InvalidWildcard => {
                "wildcard state/placement violates the SYSTEM permission grammar"
            }
            Self::ActionWildcard => "Action semantic components must not contain a wildcard",
        }
    }
}

/// Decode, validate, and evaluate one versioned semantic MessagePack
/// payload.
///
/// Returns the canonical [`EvaluationResult`] produced by the shared
/// decision loop, or a [`SemanticError`] for any malformed/incoherent
/// wire input. No decision is ever produced from malformed input.
pub fn evaluate_semantic_msgpack(payload: &[u8]) -> Result<EvaluationResult, SemanticError> {
    let wire: WireEvaluationPayload =
        rmp_serde::from_slice(payload).map_err(|_| SemanticError::MalformedPayload)?;
    if wire.version != WIRE_VERSION {
        return Err(SemanticError::UnsupportedVersion);
    }
    let action = SemanticActionInput {
        namespace: wire.action.namespace,
        resource: wire.action.resource,
        verb: wire.action.verb,
        qualifier: wire.action.qualifier,
    };
    let mut sets = Vec::with_capacity(wire.permission_sets.len());
    for wire_set in wire.permission_sets {
        let effect = match wire_set.effect.as_str() {
            "allow" => PermissionEffect::Allow,
            "deny" => PermissionEffect::Deny,
            _ => return Err(SemanticError::InvalidEffect),
        };
        let permissions = Vec::from_iter(wire_set.permissions.into_iter().map(|permission| {
            SemanticPermissionInput {
                namespace: permission.namespace,
                resource: permission.resource,
                verb: permission.verb,
                qualifier: permission.qualifier,
                qualifier_wildcard: permission.qualifier_wildcard,
            }
        }));
        sets.push(SemanticPermissionSetInput {
            effect,
            permissions,
        });
    }
    evaluate_semantic(&action, &sets)
}

/// Validate detached semantic inputs and evaluate them with the
/// canonical decision loop.
///
/// This is the semantic-input entry used by the native unit tests to
/// prove parity with the equivalent URN-input path without any
/// MessagePack layer.
pub fn evaluate_semantic(
    action: &SemanticActionInput,
    sets: &[SemanticPermissionSetInput],
) -> Result<EvaluationResult, SemanticError> {
    let parsed_action = validate_action(action)?;
    let mut parsed_sets = Vec::with_capacity(sets.len());
    for set in sets {
        let mut permissions = Vec::with_capacity(set.permissions.len());
        for permission in &set.permissions {
            permissions.push(validate_permission(permission)?);
        }
        parsed_sets.push(ParsedPolicySet {
            effect: set.effect,
            permissions,
        });
    }
    Ok(evaluate_parsed(&parsed_action, &parsed_sets))
}

fn validate_component_namespace(namespace: &str) -> Result<(), SemanticError> {
    if namespace != SYSTEM_NAMESPACE {
        return Err(SemanticError::InvalidNamespace);
    }
    Ok(())
}

fn validate_component_text(value: &str) -> Result<(), SemanticError> {
    if value.is_empty() {
        return Err(SemanticError::EmptyComponent);
    }
    if value.chars().any(char::is_whitespace) {
        return Err(SemanticError::Whitespace);
    }
    Ok(())
}

/// Validate an exact (wildcard-free) Action semantic input.
fn validate_action(action: &SemanticActionInput) -> Result<ParsedActionUrn, SemanticError> {
    validate_component_namespace(&action.namespace)?;
    validate_component_text(&action.resource)?;
    validate_component_text(&action.verb)?;
    validate_component_text(&action.qualifier)?;
    if action.resource.contains(WILDCARD)
        || action.verb.contains(WILDCARD)
        || action.qualifier.contains(WILDCARD)
    {
        return Err(SemanticError::ActionWildcard);
    }
    Ok(ParsedActionUrn {
        namespace: action.namespace.clone(),
        resource: action.resource.clone(),
        verb: action.verb.clone(),
        qualifier: action.qualifier.clone(),
    })
}

/// Validate a Permission semantic input, enforcing the explicit
/// wildcard state.
fn validate_permission(
    permission: &SemanticPermissionInput,
) -> Result<ParsedPermissionUrn, SemanticError> {
    validate_component_namespace(&permission.namespace)?;
    validate_component_text(&permission.resource)?;
    validate_component_text(&permission.verb)?;
    validate_component_text(&permission.qualifier)?;
    if permission.resource.contains(WILDCARD) || permission.verb.contains(WILDCARD) {
        return Err(SemanticError::InvalidWildcard);
    }
    if permission.qualifier_wildcard {
        // A wildcard Permission must carry exactly the complete `*`
        // qualifier; the flag and the text must agree.
        if permission.qualifier != WILDCARD {
            return Err(SemanticError::InvalidWildcard);
        }
    } else if permission.qualifier == WILDCARD || permission.qualifier.contains(WILDCARD) {
        // An exact Permission must not carry any wildcard and must not
        // claim the wildcard qualifier with the flag cleared.
        return Err(SemanticError::InvalidWildcard);
    }
    Ok(ParsedPermissionUrn {
        namespace: permission.namespace.clone(),
        resource: permission.resource.clone(),
        verb: permission.verb.clone(),
        qualifier: permission.qualifier.clone(),
    })
}

/// Build the positional wire bytes for one Action with no sets.
#[cfg(test)]
fn action_only_payload(version: u32, action: (&str, &str, &str, &str)) -> Vec<u8> {
    // Serialize the positional wire schema `[version, action, []]`.
    rmp_serde::to_vec(&(
        version,
        action,
        Vec::<(&str, Vec<(&str, &str, &str, &str, bool)>)>::new(),
    ))
    .expect("test payloads must serialize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::{DenyReason, EvaluationDecision};
    use crate::model::{ActionInput, PermissionInput, PermissionSetInput};

    // --- Fixtures ----------------------------------------------------------

    fn action_semantic() -> SemanticActionInput {
        SemanticActionInput {
            namespace: "system".to_string(),
            resource: "principal".to_string(),
            verb: "set".to_string(),
            qualifier: "active".to_string(),
        }
    }

    fn semantic_perm(
        verb: &str,
        qualifier: &str,
        qualifier_wildcard: bool,
    ) -> SemanticPermissionInput {
        SemanticPermissionInput {
            namespace: "system".to_string(),
            resource: "principal".to_string(),
            verb: verb.to_string(),
            qualifier: qualifier.to_string(),
            qualifier_wildcard,
        }
    }

    fn semantic_set(
        effect: PermissionEffect,
        permissions: Vec<SemanticPermissionInput>,
    ) -> SemanticPermissionSetInput {
        SemanticPermissionSetInput {
            effect,
            permissions,
        }
    }

    fn allow_semantic(permissions: Vec<SemanticPermissionInput>) -> SemanticPermissionSetInput {
        semantic_set(PermissionEffect::Allow, permissions)
    }

    fn deny_semantic(permissions: Vec<SemanticPermissionInput>) -> SemanticPermissionSetInput {
        semantic_set(PermissionEffect::Deny, permissions)
    }

    fn urn_action(value: &str) -> ActionInput {
        ActionInput {
            action_urn: value.to_string(),
        }
    }

    fn urn_perm(value: &str) -> PermissionInput {
        PermissionInput {
            permission_urn: value.to_string(),
        }
    }

    fn urn_set(effect: PermissionEffect, permissions: Vec<PermissionInput>) -> PermissionSetInput {
        PermissionSetInput {
            effect,
            permissions,
        }
    }

    // --- Valid v1 decode ----------------------------------------------------

    #[test]
    fn decodes_a_valid_v1_payload() {
        let payload = rmp_serde::to_vec(&(
            1u32,
            ("system", "principal", "set", "active"),
            Vec::from_iter([(
                "allow",
                Vec::from_iter([("system", "principal", "set", "active", false)]),
            )]),
        ))
        .unwrap();
        let result = evaluate_semantic_msgpack(&payload).unwrap();
        assert_eq!(result.decision, EvaluationDecision::Allow);
        assert_eq!(
            result.matched_specificity,
            Some(crate::matcher::MatchSpecificity::Exact)
        );
        assert!(result.matched_allow);
        assert!(!result.matched_deny);
        assert_eq!(result.deny_reason, None);
    }

    // --- Semantic == URN parity ---------------------------------------------

    #[test]
    fn semantic_exact_matches_urn_exact() {
        let semantic = evaluate_semantic(
            &action_semantic(),
            &[allow_semantic(Vec::from_iter([semantic_perm(
                "set", "active", false,
            )]))],
        )
        .unwrap();
        let urn = crate::evaluator::evaluate(
            &urn_action("urn:mtmf:iam:actions:system:principal:set-active"),
            &[urn_set(
                PermissionEffect::Allow,
                Vec::from_iter([urn_perm(
                    "urn:mtmf:iam:permissions:system:principal:set-active",
                )]),
            )],
        )
        .unwrap();
        assert_eq!(semantic, urn);
    }

    #[test]
    fn semantic_wildcard_matches_urn_wildcard() {
        let semantic = evaluate_semantic(
            &action_semantic(),
            &[allow_semantic(Vec::from_iter([semantic_perm(
                "set", "*", true,
            )]))],
        )
        .unwrap();
        let urn = crate::evaluator::evaluate(
            &urn_action("urn:mtmf:iam:actions:system:principal:set-active"),
            &[urn_set(
                PermissionEffect::Allow,
                Vec::from_iter([urn_perm("urn:mtmf:iam:permissions:system:principal:set-*")]),
            )],
        )
        .unwrap();
        assert_eq!(semantic, urn);
        assert_eq!(
            semantic.matched_specificity,
            Some(crate::matcher::MatchSpecificity::QualifierWildcard)
        );
    }

    #[test]
    fn semantic_no_match_matches_urn_no_match() {
        let semantic = evaluate_semantic(
            &action_semantic(),
            &[allow_semantic(Vec::from_iter([semantic_perm(
                "get", "object", false,
            )]))],
        )
        .unwrap();
        let urn = crate::evaluator::evaluate(
            &urn_action("urn:mtmf:iam:actions:system:principal:set-active"),
            &[urn_set(
                PermissionEffect::Allow,
                Vec::from_iter([urn_perm(
                    "urn:mtmf:iam:permissions:system:principal:get-object",
                )]),
            )],
        )
        .unwrap();
        assert_eq!(semantic, urn);
        assert_eq!(semantic.decision, EvaluationDecision::Deny);
        assert_eq!(semantic.deny_reason, Some(DenyReason::NoMatch));
    }

    #[test]
    fn semantic_equal_specificity_deny_conflict_matches_urn() {
        let semantic = evaluate_semantic(
            &action_semantic(),
            &[
                allow_semantic(Vec::from_iter([semantic_perm("set", "active", false)])),
                deny_semantic(Vec::from_iter([semantic_perm("set", "active", false)])),
            ],
        )
        .unwrap();
        let urn = crate::evaluator::evaluate(
            &urn_action("urn:mtmf:iam:actions:system:principal:set-active"),
            &[
                urn_set(
                    PermissionEffect::Allow,
                    Vec::from_iter([urn_perm(
                        "urn:mtmf:iam:permissions:system:principal:set-active",
                    )]),
                ),
                urn_set(
                    PermissionEffect::Deny,
                    Vec::from_iter([urn_perm(
                        "urn:mtmf:iam:permissions:system:principal:set-active",
                    )]),
                ),
            ],
        )
        .unwrap();
        assert_eq!(semantic, urn);
        assert_eq!(semantic.decision, EvaluationDecision::Deny);
        assert_eq!(semantic.deny_reason, Some(DenyReason::MatchedDeny));
        assert!(semantic.matched_allow);
        assert!(semantic.matched_deny);
    }

    #[test]
    fn semantic_wildcard_deny_does_not_defeat_exact_allow() {
        // Lower-specificity discard before effect resolution: the
        // wildcard DENY must not survive into the evidence.
        let result = evaluate_semantic(
            &action_semantic(),
            &[
                deny_semantic(Vec::from_iter([semantic_perm("set", "*", true)])),
                allow_semantic(Vec::from_iter([semantic_perm("set", "active", false)])),
            ],
        )
        .unwrap();
        assert_eq!(
            result,
            crate::evaluator::EvaluationResult::allow(crate::matcher::MatchSpecificity::Exact)
        );
        assert!(!result.matched_deny);
    }

    #[test]
    fn semantic_zero_sets_is_default_deny() {
        let result = evaluate_semantic(&action_semantic(), &[]).unwrap();
        assert_eq!(result, crate::evaluator::EvaluationResult::no_match());
    }

    #[test]
    fn semantic_repeated_evaluation_is_identical() {
        let sets = vec![allow_semantic(Vec::from_iter([semantic_perm(
            "set", "*", true,
        )]))];
        let first = evaluate_semantic(&action_semantic(), &sets).unwrap();
        for _ in 0..3 {
            assert_eq!(evaluate_semantic(&action_semantic(), &sets).unwrap(), first);
        }
    }

    // --- Unsupported version -------------------------------------------------

    #[test]
    fn unsupported_version_fails_explicitly() {
        let payload = action_only_payload(2, ("system", "principal", "set", "active"));
        assert_eq!(
            evaluate_semantic_msgpack(&payload),
            Err(SemanticError::UnsupportedVersion)
        );
    }

    #[test]
    fn version_zero_fails_explicitly() {
        let payload = action_only_payload(0, ("system", "principal", "set", "active"));
        assert_eq!(
            evaluate_semantic_msgpack(&payload),
            Err(SemanticError::UnsupportedVersion)
        );
    }

    #[test]
    fn version_is_checked_before_semantic_validation() {
        // Fully decodable structure but a non-1 version marker: the
        // version failure is explicit and never becomes a policy
        // decision, and no semantic evaluation is attempted.
        let payload = rmp_serde::to_vec(&(
            99u32,
            ("system", "principal", "set", "active"),
            Vec::<(&str, Vec<(&str, &str, &str, &str, bool)>)>::new(),
        ))
        .unwrap();
        assert_eq!(
            evaluate_semantic_msgpack(&payload),
            Err(SemanticError::UnsupportedVersion)
        );
    }

    // --- Malformed payload ---------------------------------------------------

    #[test]
    fn empty_payload_fails() {
        assert_eq!(
            evaluate_semantic_msgpack(&[]),
            Err(SemanticError::MalformedPayload)
        );
    }

    #[test]
    fn truncated_payload_fails() {
        let payload = action_only_payload(1, ("system", "principal", "set", "active"));
        assert_eq!(
            evaluate_semantic_msgpack(&payload[..payload.len() - 2]),
            Err(SemanticError::MalformedPayload)
        );
    }

    #[test]
    fn random_bytes_fail() {
        assert_eq!(
            evaluate_semantic_msgpack(&[0xb5, 0x11, 0x00, 0xff, 0x01]),
            Err(SemanticError::MalformedPayload)
        );
    }

    #[test]
    fn wrong_top_level_type_fails() {
        // A MessagePack map instead of the positional array is rejected:
        // the struct visitor finds the missing positional fields.
        let payload = rmp_serde::to_vec(&std::collections::BTreeMap::from_iter([(
            "version".to_string(),
            1u32,
        )]))
        .unwrap();
        assert_eq!(
            evaluate_semantic_msgpack(&payload),
            Err(SemanticError::MalformedPayload)
        );
    }

    #[test]
    fn missing_fields_fail() {
        // Only two of the three top-level array elements.
        let payload = rmp_serde::to_vec(&(1u32, ("system", "principal", "set", "active"))).unwrap();
        assert_eq!(
            evaluate_semantic_msgpack(&payload),
            Err(SemanticError::MalformedPayload)
        );
    }

    #[test]
    fn wrong_field_type_fails() {
        // Action namespace as an integer instead of a string.
        let payload =
            rmp_serde::to_vec(&(1u32, (5u32, "principal", "set", "active"), Vec::<()>::new()))
                .unwrap();
        assert_eq!(
            evaluate_semantic_msgpack(&payload),
            Err(SemanticError::MalformedPayload)
        );
    }

    #[test]
    fn bounded_excessive_nesting_fails() {
        // A reasonably bounded pathological nesting level (50) must fail
        // explicitly (wrong type at depth) and never produce a decision
        // or panic: `[1, [[[..."system"...]]], []]`.
        let mut inner: Vec<u8> = Vec::from_iter([0xa6]);
        inner.extend_from_slice(b"system");
        for _ in 0..50 {
            inner = Vec::from_iter([0x91]).into_iter().chain(inner).collect();
        }
        let mut payload = Vec::from_iter([0x93, 0x01]);
        payload.extend(inner);
        payload.push(0x90);
        assert_eq!(
            evaluate_semantic_msgpack(&payload),
            Err(SemanticError::MalformedPayload)
        );
    }

    // --- Semantic validation -------------------------------------------------

    #[test]
    fn wire_unknown_effect_fails() {
        let payload = rmp_serde::to_vec(&(
            1u32,
            ("system", "principal", "set", "active"),
            Vec::from_iter([(
                "maybe".to_string(),
                Vec::<(String, String, String, String, bool)>::new(),
            )]),
        ))
        .unwrap();
        assert_eq!(
            evaluate_semantic_msgpack(&payload),
            Err(SemanticError::InvalidEffect)
        );
    }

    #[test]
    fn invalid_namespace_fails() {
        let action = SemanticActionInput {
            namespace: "tenant".to_string(),
            ..action_semantic()
        };
        assert_eq!(
            evaluate_semantic(&action, &[]),
            Err(SemanticError::InvalidNamespace)
        );
    }

    #[test]
    fn empty_component_fails() {
        let action = SemanticActionInput {
            resource: "".to_string(),
            ..action_semantic()
        };
        assert_eq!(
            evaluate_semantic(&action, &[]),
            Err(SemanticError::EmptyComponent)
        );
    }

    #[test]
    fn whitespace_component_fails() {
        let action = SemanticActionInput {
            verb: "se t".to_string(),
            ..action_semantic()
        };
        assert_eq!(
            evaluate_semantic(&action, &[]),
            Err(SemanticError::Whitespace)
        );
    }

    #[test]
    fn action_wildcard_qualifier_fails() {
        let action = SemanticActionInput {
            qualifier: "ac*ve".to_string(),
            ..action_semantic()
        };
        assert_eq!(
            evaluate_semantic(&action, &[]),
            Err(SemanticError::ActionWildcard)
        );
    }

    #[test]
    fn action_complete_wildcard_qualifier_fails() {
        let action = SemanticActionInput {
            qualifier: "*".to_string(),
            ..action_semantic()
        };
        assert_eq!(
            evaluate_semantic(&action, &[]),
            Err(SemanticError::ActionWildcard)
        );
    }

    #[test]
    fn permission_resource_wildcard_fails() {
        let result = evaluate_semantic(
            &action_semantic(),
            &[allow_semantic(Vec::from_iter([SemanticPermissionInput {
                namespace: "system".to_string(),
                resource: "prin*cipal".to_string(),
                verb: "set".to_string(),
                qualifier: "*".to_string(),
                qualifier_wildcard: true,
            }]))],
        );
        assert_eq!(result, Err(SemanticError::InvalidWildcard));
    }

    #[test]
    fn permission_partial_qualifier_wildcard_fails() {
        let result = evaluate_semantic(
            &action_semantic(),
            &[allow_semantic(Vec::from_iter([semantic_perm(
                "set", "act*ve", false,
            )]))],
        );
        assert_eq!(result, Err(SemanticError::InvalidWildcard));
    }

    #[test]
    fn wildcard_flag_without_wildcard_text_fails() {
        let result = evaluate_semantic(
            &action_semantic(),
            &[allow_semantic(Vec::from_iter([semantic_perm(
                "set", "active", true,
            )]))],
        );
        assert_eq!(result, Err(SemanticError::InvalidWildcard));
    }

    #[test]
    fn wildcard_text_without_flag_fails() {
        let result = evaluate_semantic(
            &action_semantic(),
            &[allow_semantic(Vec::from_iter([semantic_perm(
                "set", "*", false,
            )]))],
        );
        assert_eq!(result, Err(SemanticError::InvalidWildcard));
    }
}
