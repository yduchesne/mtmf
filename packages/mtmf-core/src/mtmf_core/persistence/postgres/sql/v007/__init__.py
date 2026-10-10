"""Packaged versioned SQL resources for Alembic revision 0007.

The ``.sql`` files are discovered and installed in sorted filename order
by the additive ``0007_pr10_origin_lifecycle`` migration. Revision 0007
adds the explicit immutable Identity ``origin`` classification and the
ordinary-Tenant provisioning ``lifecycle`` state, their constrained
columns, updated entity read/write functions, and the origin-immutability
guard.
"""
