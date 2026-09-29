"""Revision 0001: initial MTMF physical schema.

Creates the MTMF-owned ``mtmf`` schema, the physical tables for every PR 5
persistable aggregate (Tenant, Organization, Principal, Identity, Group,
Role -> PermissionSet -> Permission, Action) and all six typed
memberships, plus PK/FK/UNIQUE/CHECK constraints, delayed foreign keys,
and precondition-supporting indexes.

Cross-table membership invariants and structural-immutability guards are
installed from the versioned packaged SQL resources in ``sql/v001``
(loaded by :func:`mtmf_core.persistence.postgres.resources.sql_version_files`).

This revision assumes an empty database and never modifies objects
outside the ``mtmf`` schema.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0001"
down_revision = None

_CREATE_TABLES = """
CREATE TABLE mtmf.tenant (
    id uuid NOT NULL,
    name text NOT NULL,
    scope smallint NOT NULL,
    owner_identity_id uuid NOT NULL,
    deletion_status smallint NOT NULL,
    extension jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT tenant_pk PRIMARY KEY (id),
    -- Legal Tenant scope values: ROOT=0, TENANT=2 (SecurityScope).
    CONSTRAINT tenant_scope_check CHECK (scope IN (0, 2)),
    -- DeletionStatus: DELETED=1, NOT_DELETED=2.
    CONSTRAINT tenant_deletion_status_check CHECK (deletion_status IN (1, 2)),
    CONSTRAINT tenant_extension_object_check CHECK (jsonb_typeof(extension) = 'object')
);

CREATE TABLE mtmf.organization (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    owner_identity_id uuid NOT NULL,
    deletion_status smallint NOT NULL,
    extension jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT organization_pk PRIMARY KEY (id),
    CONSTRAINT organization_deletion_status_check CHECK (deletion_status IN (1, 2)),
    CONSTRAINT organization_extension_object_check CHECK (jsonb_typeof(extension) = 'object')
);

CREATE TABLE mtmf.principal (
    id uuid NOT NULL,
    name text NOT NULL,
    deletion_status smallint NOT NULL,
    extension jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT principal_pk PRIMARY KEY (id),
    CONSTRAINT principal_deletion_status_check CHECK (deletion_status IN (1, 2)),
    CONSTRAINT principal_extension_object_check CHECK (jsonb_typeof(extension) = 'object')
);

CREATE TABLE mtmf.identity (
    id uuid NOT NULL,
    principal_id uuid NOT NULL,
    name text NOT NULL,
    deletion_status smallint NOT NULL,
    extension jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT identity_pk PRIMARY KEY (id),
    CONSTRAINT identity_deletion_status_check CHECK (deletion_status IN (1, 2)),
    CONSTRAINT identity_extension_object_check CHECK (jsonb_typeof(extension) = 'object')
);

CREATE TABLE mtmf.group (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    deletion_status smallint NOT NULL,
    extension jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT group_pk PRIMARY KEY (id),
    CONSTRAINT group_deletion_status_check CHECK (deletion_status IN (1, 2)),
    CONSTRAINT group_extension_object_check CHECK (jsonb_typeof(extension) = 'object')
);

CREATE TABLE mtmf.role (
    urn text NOT NULL,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    defining_tenant_id uuid NULL,
    extension jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT role_pk PRIMARY KEY (urn),
    CONSTRAINT role_extension_object_check CHECK (jsonb_typeof(extension) = 'object'),
    -- Role definition ownership: a SYSTEM Role has no structural
    -- defining Tenant; a TENANT Role requires one whose UUID agrees with
    -- the Tenant encoded in the canonical Role URN. The check follows the
    -- documented canonical URN grammar (system:<name> / tenant:<uuid>:<name>),
    -- rejects wildcards and whitespace, and keeps role names non-unique.
    CONSTRAINT role_definition_tenancy_check CHECK (
        (
            urn ~ '^urn:mtmf:iam:roles:system:[^:]+$'
            AND defining_tenant_id IS NULL
            AND urn !~ '[*[:space:]]'
        )
        OR
        (
            urn ~ (
                '^urn:mtmf:iam:roles:tenant:'
                '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
                '[0-9a-f]{4}-[0-9a-f]{12}:[^:]+$'
            )
            AND defining_tenant_id IS NOT NULL
            AND split_part(urn, ':', 6)::uuid = defining_tenant_id
            AND urn !~ '[*[:space:]]'
        )
    )
);

CREATE TABLE mtmf.permission_set (
    id uuid NOT NULL,
    role_urn text NOT NULL,
    effect text NOT NULL,
    position integer NOT NULL,
    CONSTRAINT permission_set_pk PRIMARY KEY (id),
    -- PermissionEffect backing values are the string keys 'allow'/'deny'
    -- (the domain enum is string-backed, not integer-backed).
    CONSTRAINT permission_set_effect_check CHECK (effect IN ('allow', 'deny')),
    CONSTRAINT permission_set_position_check CHECK (position >= 0),
    -- Position is structural order only; it never encodes authorization
    -- precedence.
    CONSTRAINT permission_set_role_position_unique UNIQUE (role_urn, position)
);

CREATE TABLE mtmf.permission (
    id uuid NOT NULL,
    permission_set_id uuid NOT NULL,
    urn text NOT NULL,
    position integer NOT NULL,
    CONSTRAINT permission_pk PRIMARY KEY (id),
    CONSTRAINT permission_position_check CHECK (position >= 0),
    CONSTRAINT permission_set_position_unique UNIQUE (permission_set_id, position)
    -- Permission URN is matcher semantics, intentionally NOT globally unique.
);

CREATE TABLE mtmf.action (
    urn text NOT NULL,
    CONSTRAINT action_pk PRIMARY KEY (urn)
);

CREATE TABLE mtmf.principal_tenant_membership (
    principal_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT principal_tenant_membership_pk PRIMARY KEY (principal_id, tenant_id)
);

CREATE TABLE mtmf.identity_tenant_membership (
    identity_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT identity_tenant_membership_pk PRIMARY KEY (identity_id, tenant_id)
);

CREATE TABLE mtmf.group_tenant_membership (
    group_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT group_tenant_membership_pk PRIMARY KEY (group_id, tenant_id)
);

CREATE TABLE mtmf.identity_group_membership (
    identity_id uuid NOT NULL,
    group_id uuid NOT NULL,
    CONSTRAINT identity_group_membership_pk PRIMARY KEY (identity_id, group_id)
);

CREATE TABLE mtmf.identity_org_membership (
    identity_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    CONSTRAINT identity_org_membership_pk PRIMARY KEY (identity_id, organization_id)
);

CREATE TABLE mtmf.group_org_membership (
    group_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    CONSTRAINT group_org_membership_pk PRIMARY KEY (group_id, organization_id)
);
"""

# Delayed foreign keys: entity identity tables (identity -> principal) and
# owner references exist before the referencing tables are constrained.
# Deletion is soft deletion, so FKs are restrictive (NO ACTION, the
# PostgreSQL default) and never cascade.
_FOREIGN_KEYS = """
ALTER TABLE mtmf.identity
    ADD CONSTRAINT identity_principal_fk
    FOREIGN KEY (principal_id) REFERENCES mtmf.principal (id);

ALTER TABLE mtmf.tenant
    ADD CONSTRAINT tenant_owner_identity_fk
    FOREIGN KEY (owner_identity_id) REFERENCES mtmf.identity (id);

ALTER TABLE mtmf.organization
    ADD CONSTRAINT organization_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES mtmf.tenant (id);
ALTER TABLE mtmf.organization
    ADD CONSTRAINT organization_owner_identity_fk
    FOREIGN KEY (owner_identity_id) REFERENCES mtmf.identity (id);

ALTER TABLE mtmf.group
    ADD CONSTRAINT group_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES mtmf.tenant (id);

ALTER TABLE mtmf.role
    ADD CONSTRAINT role_defining_tenant_fk
    FOREIGN KEY (defining_tenant_id) REFERENCES mtmf.tenant (id);
ALTER TABLE mtmf.permission_set
    ADD CONSTRAINT permission_set_role_fk
    FOREIGN KEY (role_urn) REFERENCES mtmf.role (urn);
ALTER TABLE mtmf.permission
    ADD CONSTRAINT permission_permission_set_fk
    FOREIGN KEY (permission_set_id) REFERENCES mtmf.permission_set (id);

ALTER TABLE mtmf.principal_tenant_membership
    ADD CONSTRAINT principal_tenant_membership_principal_fk
    FOREIGN KEY (principal_id) REFERENCES mtmf.principal (id);
ALTER TABLE mtmf.principal_tenant_membership
    ADD CONSTRAINT principal_tenant_membership_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES mtmf.tenant (id);

ALTER TABLE mtmf.identity_tenant_membership
    ADD CONSTRAINT identity_tenant_membership_identity_fk
    FOREIGN KEY (identity_id) REFERENCES mtmf.identity (id);
ALTER TABLE mtmf.identity_tenant_membership
    ADD CONSTRAINT identity_tenant_membership_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES mtmf.tenant (id);

ALTER TABLE mtmf.group_tenant_membership
    ADD CONSTRAINT group_tenant_membership_group_fk
    FOREIGN KEY (group_id) REFERENCES mtmf.group (id);
ALTER TABLE mtmf.group_tenant_membership
    ADD CONSTRAINT group_tenant_membership_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES mtmf.tenant (id);

ALTER TABLE mtmf.identity_group_membership
    ADD CONSTRAINT identity_group_membership_identity_fk
    FOREIGN KEY (identity_id) REFERENCES mtmf.identity (id);
ALTER TABLE mtmf.identity_group_membership
    ADD CONSTRAINT identity_group_membership_group_fk
    FOREIGN KEY (group_id) REFERENCES mtmf.group (id);

ALTER TABLE mtmf.identity_org_membership
    ADD CONSTRAINT identity_org_membership_identity_fk
    FOREIGN KEY (identity_id) REFERENCES mtmf.identity (id);
ALTER TABLE mtmf.identity_org_membership
    ADD CONSTRAINT identity_org_membership_organization_fk
    FOREIGN KEY (organization_id) REFERENCES mtmf.organization (id);

ALTER TABLE mtmf.group_org_membership
    ADD CONSTRAINT group_org_membership_group_fk
    FOREIGN KEY (group_id) REFERENCES mtmf.group (id);
ALTER TABLE mtmf.group_org_membership
    ADD CONSTRAINT group_org_membership_organization_fk
    FOREIGN KEY (organization_id) REFERENCES mtmf.organization (id);
"""

# Indexes that the typed membership precondition checks rely on (each
# precondition query filters a membership/entity lookup by a non-PK
# column); they also support later repository lookups.
_INDEXES = """
CREATE INDEX identity_principal_id_idx ON mtmf.identity (principal_id);
CREATE INDEX principal_tenant_membership_tenant_id_idx
    ON mtmf.principal_tenant_membership (tenant_id);
CREATE INDEX identity_tenant_membership_tenant_id_idx
    ON mtmf.identity_tenant_membership (tenant_id);
CREATE INDEX group_tenant_membership_tenant_id_idx
    ON mtmf.group_tenant_membership (tenant_id);
CREATE INDEX group_tenant_id_idx ON mtmf.group (tenant_id);
CREATE INDEX organization_tenant_id_idx ON mtmf.organization (tenant_id);
"""


def upgrade() -> None:
    """Create the MTMF schema shape and install the v001 SQL resources."""
    op.execute(_CREATE_TABLES)
    op.execute(_FOREIGN_KEYS)
    op.execute(_INDEXES)
    for path in sql_version_files("v001"):
        op.execute(path.read_text(encoding="utf-8"))
