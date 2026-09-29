-- Typed membership precondition functions.
--
-- These functions enforce the PR 2/PR 5 structural Tenant semantics at
-- the database trusted boundary. They enforce structural integrity only
-- and never authorization: no session, user, or context is consulted and
-- no cross-Tenant policy is ever evaluated here.
--
-- At write time each function reads only immutable IDs and the current
-- transaction's table state. MTMF write paths MUST insert a membership's
-- prerequisite rows before the dependent row inside one transaction
-- (immediate validation); this ordering contract is deterministic and
-- documented, and PR 7 stored functions follow it. Because membership
-- rows and structural columns are immutable (see 04_immutability_triggers.sql),
-- insert-time validation keeps the invariants valid over time.

CREATE OR REPLACE FUNCTION mtmf.identity_tenant_membership_precondition(
    identity_id_value uuid,
    tenant_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    principal_id_value uuid;
BEGIN
    SELECT principal_id INTO principal_id_value
      FROM mtmf.identity
     WHERE id = identity_id_value;
    IF principal_id_value IS NULL THEN
        RAISE EXCEPTION 'identity_tenant_membership: unknown identity';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM mtmf.principal_tenant_membership
         WHERE principal_id = principal_id_value
           AND tenant_id = tenant_id_value
    ) THEN
        RAISE EXCEPTION
          'identity_tenant_membership: missing PrincipalTenantMembership predecessor '
          'for the Identity''s Principal in the same Tenant';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_tenant_membership_precondition(
    group_id_value uuid,
    tenant_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    group_tenant uuid;
BEGIN
    SELECT tenant_id INTO group_tenant
      FROM mtmf.group
     WHERE id = group_id_value;
    IF group_tenant IS NULL THEN
        RAISE EXCEPTION 'group_tenant_membership: unknown group';
    END IF;
    IF group_tenant <> tenant_id_value THEN
        RAISE EXCEPTION
          'group_tenant_membership: Tenant disagrees with the Group structural Tenant';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_group_membership_precondition(
    identity_id_value uuid,
    group_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    group_tenant uuid;
BEGIN
    SELECT tenant_id INTO group_tenant
      FROM mtmf.group
     WHERE id = group_id_value;
    IF group_tenant IS NULL THEN
        RAISE EXCEPTION 'identity_group_membership: unknown group';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM mtmf.identity_tenant_membership
         WHERE identity_id = identity_id_value
           AND tenant_id = group_tenant
    ) THEN
        RAISE EXCEPTION
          'identity_group_membership: missing IdentityTenantMembership of the '
          'Identity in the Group''s Tenant';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_org_membership_precondition(
    identity_id_value uuid,
    organization_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    organization_tenant uuid;
BEGIN
    SELECT tenant_id INTO organization_tenant
      FROM mtmf.organization
     WHERE id = organization_id_value;
    IF organization_tenant IS NULL THEN
        RAISE EXCEPTION 'identity_org_membership: unknown organization';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM mtmf.identity_tenant_membership
         WHERE identity_id = identity_id_value
           AND tenant_id = organization_tenant
    ) THEN
        RAISE EXCEPTION
          'identity_org_membership: missing IdentityTenantMembership of the '
          'Identity in the Organization''s Tenant';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_org_membership_precondition(
    group_id_value uuid,
    organization_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    group_tenant uuid;
    organization_tenant uuid;
BEGIN
    SELECT tenant_id INTO group_tenant
      FROM mtmf.group
     WHERE id = group_id_value;
    IF group_tenant IS NULL THEN
        RAISE EXCEPTION 'group_org_membership: unknown group';
    END IF;
    SELECT tenant_id INTO organization_tenant
      FROM mtmf.organization
     WHERE id = organization_id_value;
    IF organization_tenant IS NULL THEN
        RAISE EXCEPTION 'group_org_membership: unknown organization';
    END IF;
    IF group_tenant <> organization_tenant THEN
        RAISE EXCEPTION
          'group_org_membership: Group and Organization belong to different Tenants';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM mtmf.group_tenant_membership
         WHERE group_id = group_id_value
           AND tenant_id = group_tenant
    ) THEN
        RAISE EXCEPTION
          'group_org_membership: missing GroupTenantMembership of the Group in its Tenant';
    END IF;
END;
$$;