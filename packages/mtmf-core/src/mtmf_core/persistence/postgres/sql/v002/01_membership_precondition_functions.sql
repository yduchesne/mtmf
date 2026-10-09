-- Typed membership precondition functions (v002 replacement).
--
-- Replaces the v001 definitions without editing them. The structural
-- semantics are unchanged; the difference is that each check now takes a
-- ``FOR KEY SHARE`` row lock on the prerequisite membership fact it
-- validates. That lock conflicts with the ``FOR UPDATE`` lock taken by the
-- initiating removal functions (03), so a dependent INSERT cannot race a
-- prerequisite DELETE and commit an orphan under READ COMMITTED: the
-- INSERT blocks on the lock and re-evaluates its precondition after the
-- removing transaction commits.
--
-- ``identity_group_membership_precondition`` additionally closes the v001
-- gap by requiring the Group's GroupTenantMembership to exist, in addition
-- to the Identity's IdentityTenantMembership.
--
-- These functions still enforce structural integrity only and never
-- authorization; no session, user, or role context is consulted.

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
    predecessor_locked boolean;
BEGIN
    SELECT principal_id INTO principal_id_value
      FROM mtmf.identity
     WHERE id = identity_id_value;
    IF principal_id_value IS NULL THEN
        RAISE EXCEPTION 'identity_tenant_membership: unknown identity';
    END IF;
    SELECT true INTO predecessor_locked
      FROM mtmf.principal_tenant_membership
     WHERE principal_id = principal_id_value
       AND tenant_id = tenant_id_value
       FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION
          'identity_tenant_membership: missing PrincipalTenantMembership predecessor '
          'for the Identity''s Principal in the same Tenant';
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
    predecessor_locked boolean;
BEGIN
    SELECT tenant_id INTO group_tenant
      FROM mtmf.group
     WHERE id = group_id_value;
    IF group_tenant IS NULL THEN
        RAISE EXCEPTION 'identity_group_membership: unknown group';
    END IF;
    SELECT true INTO predecessor_locked
      FROM mtmf.identity_tenant_membership
     WHERE identity_id = identity_id_value
       AND tenant_id = group_tenant
       FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION
          'identity_group_membership: missing IdentityTenantMembership of the '
          'Identity in the Group''s Tenant';
    END IF;
    SELECT true INTO predecessor_locked
      FROM mtmf.group_tenant_membership
     WHERE group_id = group_id_value
       AND tenant_id = group_tenant
       FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION
          'identity_group_membership: missing GroupTenantMembership of the '
          'Group in the Group''s Tenant';
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
    predecessor_locked boolean;
BEGIN
    SELECT tenant_id INTO organization_tenant
      FROM mtmf.organization
     WHERE id = organization_id_value;
    IF organization_tenant IS NULL THEN
        RAISE EXCEPTION 'identity_org_membership: unknown organization';
    END IF;
    SELECT true INTO predecessor_locked
      FROM mtmf.identity_tenant_membership
     WHERE identity_id = identity_id_value
       AND tenant_id = organization_tenant
       FOR KEY SHARE;
    IF NOT FOUND THEN
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
    predecessor_locked boolean;
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
    SELECT true INTO predecessor_locked
      FROM mtmf.group_tenant_membership
     WHERE group_id = group_id_value
       AND tenant_id = group_tenant
       FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION
          'group_org_membership: missing GroupTenantMembership of the Group in its Tenant';
    END IF;
END;
$$;
