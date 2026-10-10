"""Packaged versioned SQL resources for Alembic revision 0008.

The ``.sql`` files are discovered and installed in sorted filename order
by the additive ``0008_pr10_root_stewardship`` migration. Revision 0008
adds the canonical root registry, protected bootstrap, ordinary-Tenant
stewardship designation and append-only audit, and database guards that
protect root/steward state across the existing mutation paths.
"""
