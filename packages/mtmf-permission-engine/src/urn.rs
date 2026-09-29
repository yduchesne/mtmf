//! SYSTEM Action/Permission URN parsing.
//!
//! This is a narrow port of the ACTION and PERMISSION grammar from the
//! Python semantic reference (`mtmf_core.domain.iam_urn`). It is not a
//! general MTMF URN framework and it does not parse Role URNs.
//!
//! Grammar (namespace, resource, operation from the first-hyphen split):
//!
//! ```text
//! Action:     urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>
//! Permission: urn:mtmf:iam:permissions:system:<resource>:<verb>-<qualifier>
//!             urn:mtmf:iam:permissions:system:<resource>:<verb>-*
//! ```
//!
//! Only the `system` definition namespace is supported: `tenant` and
//! unknown namespaces are rejected. Action URNs are exact only. A
//! Permission URN is exact or uses the complete-qualifier wildcard `*`;
//! wildcards anywhere else are rejected.
//!
//! Parsing is fallible and deterministic: malformed input yields a
//! [`UrnParseError`] and never panics. Errors encode parsing failure
//! only — never an authorization decision.

/// Narrow parsing-failure classification for Action/Permission URNs.
///
/// Error kinds name the parsing category that failed; they carry no
/// policy meaning and are never consulted for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrnParseError {
    /// The value does not start with the expected kind prefix.
    InvalidPrefix,
    /// The colon-separated part count is not exactly three.
    InvalidComponentCount,
    /// A colon-separated component, verb, or qualifier is empty.
    EmptyComponent,
    /// A component contains whitespace.
    Whitespace,
    /// The namespace is not exactly `system`.
    UnsupportedNamespace,
    /// The operation has no `-`, or the split yields an empty part is
    /// reported as [`UrnParseError::EmptyComponent`].
    InvalidOperation,
    /// A wildcard appears where the grammar forbids it (Actions, and
    /// Permission resource/verb).
    WildcardNotAllowed,
    /// A Permission qualifier contains a wildcard other than the
    /// complete `*`.
    InvalidWildcard,
}

impl UrnParseError {
    /// A stable human-readable description of the parsing failure.
    pub fn describe(self) -> &'static str {
        match self {
            Self::InvalidPrefix => "URN must start with the expected kind prefix",
            Self::InvalidComponentCount => {
                "URN must contain exactly '<namespace>:<resource>:<operation>'"
            }
            Self::EmptyComponent => "URN components must not be empty",
            Self::Whitespace => "URN must not contain whitespace",
            Self::UnsupportedNamespace => "only the 'system' definition namespace is supported",
            Self::InvalidOperation => "operation must use the '<verb>-<qualifier>' form",
            Self::WildcardNotAllowed => "wildcard is not allowed here",
            Self::InvalidWildcard => "only the complete qualifier may be '*'",
        }
    }
}

const IAM_PREFIX: &str = "urn:mtmf:iam:";
const ACTIONS_KIND: &str = "actions";
const PERMISSIONS_KIND: &str = "permissions";
const SYSTEM_NAMESPACE: &str = "system";
pub const WILDCARD: &str = "*";

/// Parsed, validated SYSTEM Action URN components.
///
/// Carries the validated definition namespace so the matcher stays
/// structurally identical to the Python reference (which compares
/// namespaces first). Only `system` parses today, so a successful
/// Action and Permission parse can never disagree on the namespace;
/// the comparison remains for parity and future-proofing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedActionUrn {
    pub namespace: String,
    pub resource: String,
    pub verb: String,
    pub qualifier: String,
}

/// Parsed, validated SYSTEM Permission matcher URN components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPermissionUrn {
    pub namespace: String,
    pub resource: String,
    pub verb: String,
    pub qualifier: String,
}

impl ParsedPermissionUrn {
    /// True when the complete qualifier is the `*` wildcard.
    pub fn is_wildcard(&self) -> bool {
        self.qualifier == WILDCARD
    }
}

/// Split and validate the `<namespace>:<resource>:<operation>` parts
/// after the exact `<kind>` prefix.
fn split_kind_components(
    value: &str,
    kind: &str,
) -> Result<(String, String, String), UrnParseError> {
    let prefix = format!("{IAM_PREFIX}{kind}:");
    if !value.starts_with(&prefix) {
        return Err(UrnParseError::InvalidPrefix);
    }
    let remainder = &value[prefix.len()..];
    let parts = Vec::from_iter(remainder.split(":"));
    if parts.len() != 3 {
        return Err(UrnParseError::InvalidComponentCount);
    }
    let (namespace, resource, operation) = (parts[0], parts[1], parts[2]);
    if namespace.is_empty() || resource.is_empty() || operation.is_empty() {
        return Err(UrnParseError::EmptyComponent);
    }
    for part in parts {
        for character in part.chars() {
            if character.is_whitespace() {
                return Err(UrnParseError::Whitespace);
            }
        }
    }
    if namespace != SYSTEM_NAMESPACE {
        return Err(UrnParseError::UnsupportedNamespace);
    }
    Ok((
        namespace.to_string(),
        resource.to_string(),
        operation.to_string(),
    ))
}

/// Split an operation at its first hyphen into verb and qualifier.
fn split_operation(operation: &str) -> Result<(String, String), UrnParseError> {
    match operation.find('-') {
        None => Err(UrnParseError::InvalidOperation),
        Some(index) => {
            // `-` is single-byte ASCII, so the split lands on a char
            // boundary by construction.
            let verb = &operation[..index];
            let qualifier = &operation[index + 1..];
            if verb.is_empty() || qualifier.is_empty() {
                return Err(UrnParseError::EmptyComponent);
            }
            Ok((verb.to_string(), qualifier.to_string()))
        }
    }
}

fn contains_wildcard(text: &str) -> bool {
    text.contains(WILDCARD)
}

/// Parse and validate an exact SYSTEM Action URN.
///
/// Rejects wrong prefixes/kinds, wrong component counts, empty
/// components, whitespace, non-`system` namespaces, operations without
/// a `-` split, and any wildcard.
pub fn parse_action_urn(value: &str) -> Result<ParsedActionUrn, UrnParseError> {
    let (namespace, resource, operation) = split_kind_components(value, ACTIONS_KIND)?;
    let (verb, qualifier) = split_operation(&operation)?;
    if contains_wildcard(&resource) || contains_wildcard(&verb) || contains_wildcard(&qualifier) {
        return Err(UrnParseError::WildcardNotAllowed);
    }
    Ok(ParsedActionUrn {
        namespace,
        resource,
        verb,
        qualifier,
    })
}

/// Parse and validate a SYSTEM Permission matcher URN.
///
/// Rejects wrong prefixes/kinds, wrong component counts, empty
/// components, whitespace, non-`system` namespaces, operations without
/// a `-` split, wildcards in the resource or verb, and any qualifier
/// wildcard other than the complete `*`.
pub fn parse_permission_urn(value: &str) -> Result<ParsedPermissionUrn, UrnParseError> {
    let (namespace, resource, operation) = split_kind_components(value, PERMISSIONS_KIND)?;
    let (verb, qualifier) = split_operation(&operation)?;
    if contains_wildcard(&resource) || contains_wildcard(&verb) {
        return Err(UrnParseError::WildcardNotAllowed);
    }
    if qualifier != WILDCARD && contains_wildcard(&qualifier) {
        return Err(UrnParseError::InvalidWildcard);
    }
    Ok(ParsedPermissionUrn {
        namespace,
        resource,
        verb,
        qualifier,
    })
}

#[cfg(test)]
mod tests {
    use crate::urn::{
        ParsedActionUrn, ParsedPermissionUrn, SYSTEM_NAMESPACE, UrnParseError, WILDCARD,
        parse_action_urn, parse_permission_urn,
    };

    const VALID_ACTION: &str = "urn:mtmf:iam:actions:system:principal:set-active";
    const VALID_PERMISSION: &str = "urn:mtmf:iam:permissions:system:principal:set-*";

    #[test]
    fn parses_valid_system_action() {
        let parsed = parse_action_urn(VALID_ACTION).unwrap();
        assert_eq!(
            parsed,
            ParsedActionUrn {
                namespace: SYSTEM_NAMESPACE.to_string(),
                resource: "principal".to_string(),
                verb: "set".to_string(),
                qualifier: "active".to_string(),
            }
        );
        assert_eq!(parsed.namespace, "system");
    }

    #[test]
    fn parses_valid_exact_system_permission() {
        let parsed =
            parse_permission_urn("urn:mtmf:iam:permissions:system:tenant:get-object").unwrap();
        assert_eq!(
            parsed,
            ParsedPermissionUrn {
                namespace: SYSTEM_NAMESPACE.to_string(),
                resource: "tenant".to_string(),
                verb: "get".to_string(),
                qualifier: "object".to_string(),
            }
        );
        assert_eq!(parsed.namespace, "system");
        assert!(!parsed.is_wildcard());
    }

    #[test]
    fn parses_valid_complete_qualifier_wildcard_permission() {
        let parsed = parse_permission_urn(VALID_PERMISSION).unwrap();
        assert_eq!(parsed.qualifier, WILDCARD);
        assert!(parsed.is_wildcard());
        assert_eq!(parsed.verb, "set");
        assert_eq!(parsed.resource, "principal");
    }

    #[test]
    fn splits_operation_at_first_hyphen() {
        let parsed =
            parse_action_urn("urn:mtmf:iam:actions:system:principal:set-self-hosted").unwrap();
        assert_eq!(parsed.verb, "set");
        assert_eq!(parsed.qualifier, "self-hosted");
    }

    #[test]
    fn action_wildcard_qualifier_rejected() {
        assert_eq!(
            parse_action_urn("urn:mtmf:iam:actions:system:principal:set-*"),
            Err(UrnParseError::WildcardNotAllowed),
        );
    }

    #[test]
    fn action_wildcard_resource_rejected() {
        assert_eq!(
            parse_action_urn("urn:mtmf:iam:actions:system:prin*cipal:set-active"),
            Err(UrnParseError::WildcardNotAllowed),
        );
    }

    #[test]
    fn action_wildcard_verb_rejected() {
        assert_eq!(
            parse_action_urn("urn:mtmf:iam:actions:system:principal:s*t-active"),
            Err(UrnParseError::WildcardNotAllowed),
        );
    }

    #[test]
    fn permission_wildcard_resource_rejected() {
        assert_eq!(
            parse_permission_urn("urn:mtmf:iam:permissions:system:prin*cipal:set-*"),
            Err(UrnParseError::WildcardNotAllowed),
        );
    }

    #[test]
    fn permission_wildcard_verb_rejected() {
        assert_eq!(
            parse_permission_urn("urn:mtmf:iam:permissions:system:principal:s*t-*"),
            Err(UrnParseError::WildcardNotAllowed),
        );
    }

    #[test]
    fn permission_partial_qualifier_wildcard_rejected() {
        assert_eq!(
            parse_permission_urn("urn:mtmf:iam:permissions:system:principal:set-act*ve"),
            Err(UrnParseError::InvalidWildcard),
        );
        assert_eq!(
            parse_permission_urn("urn:mtmf:iam:permissions:system:principal:set-al*"),
            Err(UrnParseError::InvalidWildcard),
        );
    }

    // The plan's invalid matrix (section 13): every category must be
    // rejected with the classified kind. Cases are table-driven.

    #[test]
    fn rejects_every_invalid_action_category() {
        let cases = [
            // wrong prefix
            (
                "urn:wrong:iam:actions:system:principal:set-active",
                UrnParseError::InvalidPrefix,
            ),
            // Permission kind used as Action
            (
                "urn:mtmf:iam:permissions:system:principal:set-active",
                UrnParseError::InvalidPrefix,
            ),
            // missing namespace
            (
                "urn:mtmf:iam:actions::principal:set-active",
                UrnParseError::EmptyComponent,
            ),
            // tenant namespace
            (
                "urn:mtmf:iam:actions:tenant:principal:set-active",
                UrnParseError::UnsupportedNamespace,
            ),
            // unknown namespace
            (
                "urn:mtmf:iam:actions:vendor:principal:set-active",
                UrnParseError::UnsupportedNamespace,
            ),
            // empty resource
            (
                "urn:mtmf:iam:actions:system::set-active",
                UrnParseError::EmptyComponent,
            ),
            // missing operation hyphen
            (
                "urn:mtmf:iam:actions:system:principal:setactive",
                UrnParseError::InvalidOperation,
            ),
            // empty verb
            (
                "urn:mtmf:iam:actions:system:principal:-active",
                UrnParseError::EmptyComponent,
            ),
            // empty qualifier
            (
                "urn:mtmf:iam:actions:system:principal:set-",
                UrnParseError::EmptyComponent,
            ),
            // wildcard resource
            (
                "urn:mtmf:iam:actions:system:prin*cipal:set-active",
                UrnParseError::WildcardNotAllowed,
            ),
            // wildcard verb
            (
                "urn:mtmf:iam:actions:system:principal:s*t-active",
                UrnParseError::WildcardNotAllowed,
            ),
            // wildcard qualifier (Action is exact only)
            (
                "urn:mtmf:iam:actions:system:principal:set-*",
                UrnParseError::WildcardNotAllowed,
            ),
            // partial wildcard in the qualifier
            (
                "urn:mtmf:iam:actions:system:principal:set-act*ve",
                UrnParseError::WildcardNotAllowed,
            ),
            // whitespace within a component
            (
                "urn:mtmf:iam:actions:system:principal:set -active",
                UrnParseError::Whitespace,
            ),
            // extra component
            (
                "urn:mtmf:iam:actions:system:principal:set-active:extra",
                UrnParseError::InvalidComponentCount,
            ),
        ];
        for (text, expected) in cases {
            let message = format!("unexpected result for {text:?}");
            assert_eq!(parse_action_urn(text), Err(expected), "{message}");
        }
    }

    #[test]
    fn rejects_every_invalid_permission_category() {
        let cases = [
            // wrong prefix
            (
                "urn:wrong:iam:permissions:system:principal:set-active",
                UrnParseError::InvalidPrefix,
            ),
            // Action kind used as Permission
            (
                "urn:mtmf:iam:actions:system:principal:set-active",
                UrnParseError::InvalidPrefix,
            ),
            // missing namespace
            (
                "urn:mtmf:iam:permissions::principal:set-active",
                UrnParseError::EmptyComponent,
            ),
            // tenant namespace
            (
                "urn:mtmf:iam:permissions:tenant:principal:set-active",
                UrnParseError::UnsupportedNamespace,
            ),
            // unknown namespace
            (
                "urn:mtmf:iam:permissions:vendor:principal:set-active",
                UrnParseError::UnsupportedNamespace,
            ),
            // empty resource
            (
                "urn:mtmf:iam:permissions:system::set-*",
                UrnParseError::EmptyComponent,
            ),
            // missing operation hyphen
            (
                "urn:mtmf:iam:permissions:system:principal:setactive",
                UrnParseError::InvalidOperation,
            ),
            // empty verb
            (
                "urn:mtmf:iam:permissions:system:principal:-active",
                UrnParseError::EmptyComponent,
            ),
            // empty qualifier
            (
                "urn:mtmf:iam:permissions:system:principal:set-",
                UrnParseError::EmptyComponent,
            ),
            // wildcard resource
            (
                "urn:mtmf:iam:permissions:system:prin*cipal:set-*",
                UrnParseError::WildcardNotAllowed,
            ),
            // wildcard verb
            (
                "urn:mtmf:iam:permissions:system:principal:s*t-*",
                UrnParseError::WildcardNotAllowed,
            ),
            // partial/embedded qualifier wildcard
            (
                "urn:mtmf:iam:permissions:system:principal:set-act*ve",
                UrnParseError::InvalidWildcard,
            ),
            // whitespace
            (
                "urn:mtmf:iam:permissions:system:principal:set -active",
                UrnParseError::Whitespace,
            ),
            // extra component
            (
                "urn:mtmf:iam:permissions:system:principal:set-active:extra",
                UrnParseError::InvalidComponentCount,
            ),
        ];
        for (text, expected) in cases {
            let message = format!("unexpected result for {text:?}");
            assert_eq!(parse_permission_urn(text), Err(expected), "{message}");
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        // A sample of pathological inputs must all return Err, not
        // panic and not silently parse.
        for text in [
            "",
            ":",
            "urn:",
            "urn:mtmf:iam:actions:",
            "urn:mtmf:iam:actions:::",
            "urn:mtmf:iam:actions:system:principal:set-active:", // trailing colon
            "urn:mtmf:iam:actions:system:principal:-",
            "urn:mtmf:iam:actions:system:::-",
            "urn:mtmf:iam:actions:system:principal:verb-qual*", // partial wildcard in Action
            "urn:mtmf:iam:permissions:system:principal:*",
        ] {
            // Whatever the classification, the result must be Err for
            // both the Action and the Permission parser: malformed text
            // never panics and never parses under either grammar.
            let action_outcome = parse_action_urn(text);
            let permission_outcome = parse_permission_urn(text);
            let action_message = format!("action parse expected Err for {text:?}");
            let permission_message = format!("permission parse expected Err for {text:?}");
            assert!(action_outcome.is_err(), "{action_message}");
            assert!(permission_outcome.is_err(), "{permission_message}");
        }
    }

    #[test]
    fn parsing_is_deterministic() {
        let first = parse_action_urn(VALID_ACTION);
        let second = parse_action_urn(VALID_ACTION);
        assert_eq!(first, second);
        let first_permission = parse_permission_urn(VALID_PERMISSION);
        let second_permission = parse_permission_urn(VALID_PERMISSION);
        assert_eq!(first_permission, second_permission);
    }
}
