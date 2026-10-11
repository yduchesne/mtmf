"""Packaged versioned SQL resources for Alembic revision 0010.

The ``.sql`` files are discovered and installed in sorted filename order
by the additive ``0010_pr13_application_registry`` migration. Revision
0010 adds the Application registry, Application-Tenant registration, and
Tenant subscription schema, database immutability/lifecycle guards,
operator-only mutation functions, and the narrowly reviewed runtime read
functions.
"""
