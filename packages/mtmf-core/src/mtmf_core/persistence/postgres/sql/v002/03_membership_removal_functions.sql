-- Sanctioned membership removal operations (v002).
--
-- These SECURITY INVOKER, schema-qualified functions are the only supported
-- way to remove a Tenant membership. In one transaction each function:
--
--   1. locks the initiating membership row ``FOR UPDATE`` (and, for a
--      Principal removal, every owned Identity-Tenant membership in the
--      Tenant) so concurrent dependent INSERTs block on their
--      ``FOR KEY SHARE`` precondition lock and re-check after commit;
--   2. physically DELETEs the Tenant-scoped dependents and the initiating
--      row, collecting actual affected-row counts with ``ROW_COUNT`` (never
--      pre-delete estimates);
--   3. inserts exactly one compact operation-level audit row.
--
-- Removing a nonexistent initiating row is a documented no-op: it deletes
-- nothing and writes no audit row. Concurrent duplicate removals serialize
-- on the initiating row lock, so at most one succeeds and writes the single
-- audit row. Any failure rolls the whole operation (deletes and audit) back.
--
-- Tenant scoping is always derived from the authoritative entity rows
-- (``organization.tenant_id``, ``group.tenant_id``); the caller Tenant is
-- never trusted on its own.

CREATE OR REPLACE FUNCTION mtmf.remove_identity_tenant_membership(
    identity_id_value uuid,
    tenant_id_value uuid,
    actor_identity_id_value uuid DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    identity_org_count bigint := 0;
    identity_group_count bigint := 0;
    identity_tenant_count bigint := 0;
    locked boolean;
BEGIN
    SELECT true INTO locked
      FROM mtmf.identity_tenant_membership
     WHERE identity_id = identity_id_value
       AND tenant_id = tenant_id_value
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    PERFORM set_config('mtmf.membership_removal', 'on', true);

    DELETE FROM mtmf.identity_org_membership
     WHERE identity_id = identity_id_value
       AND organization_id IN (
           SELECT id FROM mtmf.organization WHERE tenant_id = tenant_id_value
       );
    GET DIAGNOSTICS identity_org_count = ROW_COUNT;

    DELETE FROM mtmf.identity_group_membership
     WHERE identity_id = identity_id_value
       AND group_id IN (
           SELECT id FROM mtmf.group WHERE tenant_id = tenant_id_value
       );
    GET DIAGNOSTICS identity_group_count = ROW_COUNT;

    DELETE FROM mtmf.identity_tenant_membership
     WHERE identity_id = identity_id_value
       AND tenant_id = tenant_id_value;
    GET DIAGNOSTICS identity_tenant_count = ROW_COUNT;

    PERFORM set_config('mtmf.membership_removal', 'off', true);

    INSERT INTO mtmf.membership_removal_audit (
        initiating_kind,
        tenant_id,
        identity_id,
        actor_identity_id,
        identity_tenant_count,
        identity_group_count,
        identity_org_count
    ) VALUES (
        'identity_tenant_membership',
        tenant_id_value,
        identity_id_value,
        actor_identity_id_value,
        identity_tenant_count,
        identity_group_count,
        identity_org_count
    );
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.remove_group_tenant_membership(
    group_id_value uuid,
    tenant_id_value uuid,
    actor_identity_id_value uuid DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    group_org_count bigint := 0;
    identity_group_count bigint := 0;
    group_tenant_count bigint := 0;
    locked boolean;
BEGIN
    SELECT true INTO locked
      FROM mtmf.group_tenant_membership
     WHERE group_id = group_id_value
       AND tenant_id = tenant_id_value
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- The caller Tenant must agree with the Group's immutable structural
    -- Tenant; exclusivity is asserted from the authoritative Group row.
    PERFORM 1
      FROM mtmf.group
     WHERE id = group_id_value
       AND tenant_id = tenant_id_value;
    IF NOT FOUND THEN
        RAISE EXCEPTION
          'remove_group_tenant_membership: Tenant disagrees with the Group structural Tenant';
    END IF;

    PERFORM set_config('mtmf.membership_removal', 'on', true);

    DELETE FROM mtmf.group_org_membership
     WHERE group_id = group_id_value
       AND organization_id IN (
           SELECT id FROM mtmf.organization WHERE tenant_id = tenant_id_value
       );
    GET DIAGNOSTICS group_org_count = ROW_COUNT;

    -- A Group is exclusive to one Tenant, so every IdentityGroupMembership
    -- for the Group is within the verified Tenant.
    DELETE FROM mtmf.identity_group_membership
     WHERE group_id = group_id_value;
    GET DIAGNOSTICS identity_group_count = ROW_COUNT;

    DELETE FROM mtmf.group_tenant_membership
     WHERE group_id = group_id_value
       AND tenant_id = tenant_id_value;
    GET DIAGNOSTICS group_tenant_count = ROW_COUNT;

    PERFORM set_config('mtmf.membership_removal', 'off', true);

    INSERT INTO mtmf.membership_removal_audit (
        initiating_kind,
        tenant_id,
        group_id,
        actor_identity_id,
        group_tenant_count,
        group_org_count,
        identity_group_count
    ) VALUES (
        'group_tenant_membership',
        tenant_id_value,
        group_id_value,
        actor_identity_id_value,
        group_tenant_count,
        group_org_count,
        identity_group_count
    );
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.remove_principal_tenant_membership(
    principal_id_value uuid,
    tenant_id_value uuid,
    actor_identity_id_value uuid DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    identity_org_count bigint := 0;
    identity_group_count bigint := 0;
    identity_tenant_count bigint := 0;
    principal_tenant_count bigint := 0;
    locked boolean;
BEGIN
    SELECT true INTO locked
      FROM mtmf.principal_tenant_membership
     WHERE principal_id = principal_id_value
       AND tenant_id = tenant_id_value
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- Lock every owned Identity-Tenant membership in this Tenant before
    -- deleting any dependent, so no dependent INSERT can slip in for an
    -- Identity whose Tenant membership is about to be removed.
    PERFORM 1
      FROM mtmf.identity_tenant_membership AS itm
      JOIN mtmf.identity AS i ON i.id = itm.identity_id
     WHERE i.principal_id = principal_id_value
       AND itm.tenant_id = tenant_id_value
       FOR UPDATE OF itm;

    PERFORM set_config('mtmf.membership_removal', 'on', true);

    DELETE FROM mtmf.identity_org_membership
     WHERE identity_id IN (
           SELECT id FROM mtmf.identity WHERE principal_id = principal_id_value
       )
       AND organization_id IN (
           SELECT id FROM mtmf.organization WHERE tenant_id = tenant_id_value
       );
    GET DIAGNOSTICS identity_org_count = ROW_COUNT;

    DELETE FROM mtmf.identity_group_membership
     WHERE identity_id IN (
           SELECT id FROM mtmf.identity WHERE principal_id = principal_id_value
       )
       AND group_id IN (
           SELECT id FROM mtmf.group WHERE tenant_id = tenant_id_value
       );
    GET DIAGNOSTICS identity_group_count = ROW_COUNT;

    DELETE FROM mtmf.identity_tenant_membership
     WHERE identity_id IN (
           SELECT id FROM mtmf.identity WHERE principal_id = principal_id_value
       )
       AND tenant_id = tenant_id_value;
    GET DIAGNOSTICS identity_tenant_count = ROW_COUNT;

    DELETE FROM mtmf.principal_tenant_membership
     WHERE principal_id = principal_id_value
       AND tenant_id = tenant_id_value;
    GET DIAGNOSTICS principal_tenant_count = ROW_COUNT;

    PERFORM set_config('mtmf.membership_removal', 'off', true);

    INSERT INTO mtmf.membership_removal_audit (
        initiating_kind,
        tenant_id,
        principal_id,
        actor_identity_id,
        principal_tenant_count,
        identity_tenant_count,
        identity_group_count,
        identity_org_count
    ) VALUES (
        'principal_tenant_membership',
        tenant_id_value,
        principal_id_value,
        actor_identity_id_value,
        principal_tenant_count,
        identity_tenant_count,
        identity_group_count,
        identity_org_count
    );
    RETURN true;
END;
$$;
