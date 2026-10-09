"""Revision 0002: membership removal cascades, compact audit, and guards.

Adds the physical-deletion trust boundary for the six typed membership
relationships documented in ``docs/DOMAIN_MODEL.md`` and
``docs/SECURITY_MODEL.md``:

- the append-only ``mtmf.membership_removal_audit`` table (exactly one
  compact operation-level row per initiating removal, with actual
  affected-row counts by membership type and no per-dependent history);
- the ``group_tenant_membership`` Group-exclusivity constraint;
- the versioned ``sql/v002`` resources that replace the v001 membership
  precondition functions (adding ``FOR KEY SHARE`` predecessor locks and
  the missing GroupTenantMembership check for IdentityGroupMembership),
  install the membership DELETE guard, and install the sanctioned
  Principal/Identity/Group Tenant-membership removal functions.

Revision ``0001`` and the packaged ``sql/v001`` resources are never
modified. Only upgrade-to-head is part of the MTMF migration contract;
there is no supported downgrade, so audit data is never silently
discarded.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0002"
down_revision = "0001"

_CREATE_MEMBERSHIP_REMOVAL_AUDIT = """
CREATE TABLE mtmf.membership_removal_audit (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    initiating_kind text NOT NULL,
    tenant_id uuid NOT NULL,
    principal_id uuid NULL,
    identity_id uuid NULL,
    group_id uuid NULL,
    organization_id uuid NULL,
    actor_identity_id uuid NULL,
    principal_tenant_count bigint NOT NULL DEFAULT 0,
    identity_tenant_count bigint NOT NULL DEFAULT 0,
    group_tenant_count bigint NOT NULL DEFAULT 0,
    identity_group_count bigint NOT NULL DEFAULT 0,
    identity_org_count bigint NOT NULL DEFAULT 0,
    group_org_count bigint NOT NULL DEFAULT 0,
    CONSTRAINT membership_removal_audit_pk PRIMARY KEY (id),
    -- The initiating typed relationship is a constrained value, never an
    -- unbounded free-form string.
    CONSTRAINT membership_removal_audit_kind_check CHECK (
        initiating_kind IN (
            'principal_tenant_membership',
            'identity_tenant_membership',
            'group_tenant_membership',
            'identity_group_membership',
            'identity_org_membership',
            'group_org_membership'
        )
    ),
    -- Participant columns are typed scalars; their shape is fixed by the
    -- initiating kind so the record is never an ambiguous polymorphic join.
    CONSTRAINT membership_removal_audit_participants_check CHECK (
        (
            initiating_kind = 'principal_tenant_membership'
            AND principal_id IS NOT NULL
            AND identity_id IS NULL AND group_id IS NULL AND organization_id IS NULL
        )
        OR (
            initiating_kind = 'identity_tenant_membership'
            AND identity_id IS NOT NULL
            AND principal_id IS NULL AND group_id IS NULL AND organization_id IS NULL
        )
        OR (
            initiating_kind = 'group_tenant_membership'
            AND group_id IS NOT NULL
            AND principal_id IS NULL AND identity_id IS NULL AND organization_id IS NULL
        )
        OR (
            initiating_kind = 'identity_group_membership'
            AND identity_id IS NOT NULL AND group_id IS NOT NULL
            AND principal_id IS NULL AND organization_id IS NULL
        )
        OR (
            initiating_kind = 'identity_org_membership'
            AND identity_id IS NOT NULL AND organization_id IS NOT NULL
            AND principal_id IS NULL AND group_id IS NULL
        )
        OR (
            initiating_kind = 'group_org_membership'
            AND group_id IS NOT NULL AND organization_id IS NOT NULL
            AND principal_id IS NULL AND identity_id IS NULL
        )
    ),
    CONSTRAINT membership_removal_audit_counts_check CHECK (
        principal_tenant_count >= 0
        AND identity_tenant_count >= 0
        AND group_tenant_count >= 0
        AND identity_group_count >= 0
        AND identity_org_count >= 0
        AND group_org_count >= 0
    ),
    -- The initiating row is always physically removed, so its own count is
    -- at least one; a no-op removal writes no audit row at all.
    CONSTRAINT membership_removal_audit_initiator_count_check CHECK (
        (initiating_kind = 'principal_tenant_membership' AND principal_tenant_count >= 1)
        OR (initiating_kind = 'identity_tenant_membership' AND identity_tenant_count >= 1)
        OR (initiating_kind = 'group_tenant_membership' AND group_tenant_count >= 1)
        OR (initiating_kind = 'identity_group_membership' AND identity_group_count >= 1)
        OR (initiating_kind = 'identity_org_membership' AND identity_org_count >= 1)
        OR (initiating_kind = 'group_org_membership' AND group_org_count >= 1)
    )
);
"""

# A Group is exclusive to exactly one Tenant. The precondition already ties
# GroupTenantMembership.tenant_id to the immutable group.tenant_id; this
# constraint additionally forbids a second membership row structurally and
# makes the migration fail loudly if pre-existing data violated the rule.
_GROUP_TENANT_EXCLUSIVITY = """
ALTER TABLE mtmf.group_tenant_membership
    ADD CONSTRAINT group_tenant_membership_group_exclusive UNIQUE (group_id);
"""

# The actor is an immutable historical reference, never fabricated. An FK
# with no cascading action keeps it pointing at a real Identity (entity rows
# are soft-deleted, so provenance survives), and a bad actor fails the whole
# removal transaction before anything commits.
_AUDIT_ACTOR_FK = """
ALTER TABLE mtmf.membership_removal_audit
    ADD CONSTRAINT membership_removal_audit_actor_identity_fk
    FOREIGN KEY (actor_identity_id) REFERENCES mtmf.identity (id);
"""


_VALIDATE_EXISTING_DATA = """
DO $$
BEGIN
    -- Revision 0002 newly requires GroupTenantMembership for every
    -- IdentityGroupMembership. v001 did not, so an upgrade must fail loudly
    -- if existing data violates the new invariant instead of silently
    -- deleting or ignoring it.
    IF EXISTS (
        SELECT 1
          FROM mtmf.identity_group_membership AS igm
         WHERE NOT EXISTS (
               SELECT 1
                 FROM mtmf.group_tenant_membership AS gtm
                WHERE gtm.group_id = igm.group_id
         )
    ) THEN
        RAISE EXCEPTION
          'revision 0002 cannot upgrade: IdentityGroupMembership rows exist without '
          'the GroupTenantMembership prerequisite; resolve the data explicitly';
    END IF;
END;
$$;
"""


def upgrade() -> None:
    """Create the removal audit table and install the v002 SQL resources."""
    op.execute(_VALIDATE_EXISTING_DATA)
    op.execute(_CREATE_MEMBERSHIP_REMOVAL_AUDIT)
    op.execute(_GROUP_TENANT_EXCLUSIVITY)
    op.execute(_AUDIT_ACTOR_FK)
    for path in sql_version_files("v002"):
        op.execute(path.read_text(encoding="utf-8"))
