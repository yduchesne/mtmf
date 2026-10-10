"""Packaged versioned SQL resources for Alembic revision 0009.

The ``.sql`` files are discovered and installed in sorted filename order
by the additive ``0009_pr11_tenant_management_group`` migration. Revision
0009 adds the TenantManagementGroup structural schema, the two approved
SYSTEM management Roles, explicit managed-Tenant and Identity eligibility
relationships, database guards, atomic ROOT bootstrap integration, and
narrow runtime read functions.
"""
