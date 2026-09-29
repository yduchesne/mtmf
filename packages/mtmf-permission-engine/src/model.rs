//! Detached native MTMF permission-policy model (PR 8B).
//!
//! These are the primitive, detached policy-input shapes the private
//! Rust kernel will consume once evaluation exists (PR 8C). PR 8B only
//! defines the structures: nothing in this module evaluates policy,
//! resolves PermissionSet effects, or produces an authorization
//! decision, and no live MTMF Python domain object (`Action`, `Role`,
//! `PermissionSet`, `Permission`) crosses the FFI boundary into these
//! types.
//!
//! The shapes intentionally carry no Tenant, Organization, Principal,
//! Identity, Group, RoleAssignment, membership, session, target, scope,
//! stewardship, or TenantManagementGroup state: Rust evaluates policy
//! only. The compiler enforces the absence of context fields: each
//! struct below has exactly the detached policy fields its constructor
//! declares.

/// The effect attached to a detached PermissionSet.
///
/// Exactly `Allow` and `Deny` exist. The PR 8C evaluator reads the
/// effect from the containing [`PermissionSetInput`]; the single
/// Permission matcher in `matcher.rs` never inspects this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionEffect {
    Allow,
    Deny,
}

/// Detached exact-Action input: the primitive canonical Action URN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionInput {
    pub action_urn: String,
}

/// Detached Permission matcher input: the primitive matcher URN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionInput {
    pub permission_urn: String,
}

/// Detached PermissionSet input: one effect plus the owned Permissions.
///
/// The PR 8C evaluator consumes this value but never mutates it; the
/// matcher still never consults `effect` (that is the evaluator's
/// job). The effect is the only source of ALLOW/DENY authority for the
/// Permissions it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSetInput {
    pub effect: PermissionEffect,
    pub permissions: Vec<PermissionInput>,
}

#[cfg(test)]
mod tests {
    use crate::model::{ActionInput, PermissionEffect, PermissionInput, PermissionSetInput};

    fn action_urn(value: &str) -> String {
        value.to_string()
    }

    fn permission_urn(value: &str) -> String {
        value.to_string()
    }

    #[test]
    fn permission_set_can_hold_allow_set_with_two_permissions() {
        let set = PermissionSetInput {
            effect: PermissionEffect::Allow,
            permissions: Vec::from_iter([
                PermissionInput {
                    permission_urn: permission_urn(
                        "urn:mtmf:iam:permissions:system:principal:set-active",
                    ),
                },
                PermissionInput {
                    permission_urn: permission_urn(
                        "urn:mtmf:iam:permissions:system:principal:set-*",
                    ),
                },
            ]),
        };
        assert_eq!(set.effect, PermissionEffect::Allow);
        assert_eq!(set.permissions.len(), 2);
        assert_eq!(
            set.permissions[0].permission_urn,
            "urn:mtmf:iam:permissions:system:principal:set-active"
        );
        assert_eq!(
            set.permissions[1].permission_urn,
            "urn:mtmf:iam:permissions:system:principal:set-*"
        );
    }

    #[test]
    fn permission_set_can_hold_deny_set_with_one_permission() {
        let set = PermissionSetInput {
            effect: PermissionEffect::Deny,
            permissions: Vec::from_iter([PermissionInput {
                permission_urn: permission_urn(
                    "urn:mtmf:iam:permissions:system:principal:set-inactive",
                ),
            }]),
        };
        assert_eq!(set.effect, PermissionEffect::Deny);
        assert_eq!(set.permissions.len(), 1);
    }

    #[test]
    fn effects_are_exactly_allow_and_deny() {
        // The enum has exactly the two documented variants; there is no
        // third "neutral" effect that could smuggle a decision into the
        // detached structure.
        let allow = PermissionEffect::Allow;
        let deny = PermissionEffect::Deny;
        assert_ne!(allow, deny);
    }

    #[test]
    fn action_input_carries_only_a_primitive_urn() {
        let action = ActionInput {
            action_urn: action_urn("urn:mtmf:iam:actions:system:principal:set-active"),
        };
        assert_eq!(
            action.action_urn,
            "urn:mtmf:iam:actions:system:principal:set-active"
        );
    }

    #[test]
    fn model_shapes_carry_no_domain_or_authorization_state() {
        // The types are plain data holders over primitive URN text and
        // the effect enum. Structural trickery (extra fields, embedded
        // Role/Tenant/decision state) would be a compile-time API
        // change; these assertions pin the documented surface so a
        // review notices any drift.
        let set = PermissionSetInput {
            effect: PermissionEffect::Allow,
            permissions: Vec::new(),
        };
        assert_ne!(
            set,
            PermissionSetInput {
                effect: PermissionEffect::Deny,
                permissions: Vec::new(),
            }
        );
        assert_eq!(set.permissions.len(), 0);
    }
}
