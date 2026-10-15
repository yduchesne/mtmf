# PR21_FINAL_SHA

- **Base (fresh `main`) SHA:** `455ae7a35d090b2546afa0c78fc9e4750ffee5ec`
- **Documentation commit under test (post-change gates ran here):**
  `4bcffdafe67e4d2bacad6a9aa058cf1acd091191`
- **Branch:** `dev/onboarding-foundation`
- **Final PR tip:** the commit whose parent is `4bcffda`; it adds this
  record plus the ownership/trust-flow diagram to
  `docs/ONBOARDING_ARCHITECTURE.md`. It contains no production or wire-contract
  change, and the pre-commit hook (gitleaks, `--rust`, `--qa`, `--sec`) re-ran
  and passed on that tree.

The four canonical gates and the pre-commit hook (gitleaks, `--rust`, `--qa`,
`--sec`) passed at `4bcffda`. See `PR21_ACCEPTANCE_REPORT.md` §4 for evidence.
