"""Packaged versioned SQL resources for Alembic revision 0006.

The ``.sql`` files are discovered and installed in sorted filename order
by the additive ``0006_pr10_builtin_policy`` migration. Revision 0006
installs the approved Gate M minimum built-in IAM seed (merge of PR #38)
and protects the resulting SYSTEM-owned Role definitions from ordinary
runtime mutation.
"""
