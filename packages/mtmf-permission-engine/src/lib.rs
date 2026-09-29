//! Private MTMF permission-engine crate root (PR 8A foundation, PR 8B
//! model + matcher).
//!
//! The crate is the deterministic in-memory permission-policy kernel for
//! MTMF. Rust evaluates policy only: it never retrieves session, Tenant,
//! membership, assignment, stewardship, or delegation context, and
//! performs no I/O (no PostgreSQL, `MtmfSpi`, repositories, network,
//! filesystem policy discovery, async runtime, background thread, or
//! cache).
//!
//! PR 8B adds the detached native policy model (`model.rs`), the SYSTEM
//! Action/Permission URN parsers (`urn.rs`), and the single-Permission
//! matcher with match specificity (`matcher.rs`). No ALLOW/DENY
//! resolution, no PermissionSet evaluation, no default DENY, and no
//! decision type exists: 8B makes no authorization decision, and the
//! Python `PermissionEvaluator`/`Authorizer` remain authoritative and
//! unchanged.
//!
//! The only surface exposed to Python is the private PyO3 module plus a
//! small primitive matcher bridge. Inputs are detached primitive values
//! only: no live MTMF Python domain object crosses the FFI boundary and
//! no JSON serialization carries policy.

use pyo3::prelude::*;

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
/// Exposes the deterministic capability API (PR 8A) and the smallest
/// primitive single-Permission matcher bridge (PR 8B). No policy
/// classes are exposed and nothing here authorizes.
#[pymodule]
mod _mtmf_permission_engine {
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;

    use crate::matcher::{MatchResult, MatchSpecificity, match_permission_urns};
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
