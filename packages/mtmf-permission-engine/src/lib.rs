//! Private MTMF permission-engine foundation (PR 8A).
//!
//! This crate is the deterministic in-memory permission-policy foundation
//! for MTMF. PR 8A intentionally implements no permission semantics:
//! there is no Action/Permission parsing, no wildcard matching, no
//! specificity, no ALLOW/DENY resolution, and no decision type. The
//! Python evaluator (`mtmf_core.authorization.permission_evaluator`)
//! remains the active semantic implementation, and the Python
//! `Authorizer` remains authoritative.
//!
//! The only surface exposed to Python is a deterministic
//! smoke/capability API. The future boundary (PR 8B+) is:
//!
//! ```text
//! exact Action + already-applicable PermissionSets -> evaluation result
//! ```
//!
//! Rust will receive detached primitive policy input only. It never
//! retrieves session, Tenant, membership, assignment, stewardship, or
//! delegation context, and performs no I/O.

use pyo3::prelude::*;

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

/// Python module: private `_mtmf_permission_engine` capability surface.
#[pymodule]
mod _mtmf_permission_engine {
    use pyo3::prelude::*;

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
