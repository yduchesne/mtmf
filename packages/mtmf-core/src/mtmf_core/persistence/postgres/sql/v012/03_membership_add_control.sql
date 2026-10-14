-- v012: verified Identity-to-Group membership add (PR 19C).
--
-- Two owner-owned SECURITY DEFINER entry points, both fixed ``search_path = ''``
-- and schema-qualified with no dynamic SQL:
--
--   * ``identity_group_membership_add_lock`` performs the bounded, ordered
--     row-lock/recheck protocol (Amendment 01 §D) and validates every mutable
--     authorization/target prerequisite inside the caller's transaction. It
--     takes no authorization decision; it makes the subsequent authoritative
--     ALLOW stable until commit.
--
--   * ``identity_group_membership_add_verified`` inserts the membership and,
--     iff a row was actually inserted, exactly one append-only audit row in
--     the same statement/transaction. It independently re-validates the
--     structural target binding and the steward guard as defense in depth.
--
-- The database validates structural consistency only. It cannot and does not
-- attest external token verification or the Action ALLOW; provenance is
-- application-verified, not database-attested.

CREATE OR REPLACE FUNCTION mtmf.identity_group_membership_add_lock(
    tenant_id_value uuid,
    actor_identity_id_value uuid,
    subject_identity_id_value uuid,
    group_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    tenant_scope smallint;
    tenant_lifecycle smallint;
    tenant_deletion smallint;
    designation_identity uuid;
    actor_principal uuid;
    group_tenant uuid;
    locked boolean;
BEGIN
    IF tenant_id_value IS NULL OR actor_identity_id_value IS NULL
       OR subject_identity_id_value IS NULL OR group_id_value IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add lock requires complete identifiers';
    END IF;

    -- 1. Tenant row (blocks lifecycle/suspension changes).
    SELECT scope, lifecycle, deletion_status
      INTO tenant_scope, tenant_lifecycle, tenant_deletion
      FROM mtmf.tenant
     WHERE id = tenant_id_value
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'membership-add target Tenant is unknown';
    END IF;
    IF tenant_scope <> 2 OR tenant_lifecycle <> 1 OR tenant_deletion <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add requires an active ordinary Tenant';
    END IF;

    -- 2. Stewardship designation row (blocks concurrent replacement).
    SELECT designated_identity_id
      INTO designation_identity
      FROM mtmf.stewardship_designation
     WHERE tenant_id = tenant_id_value
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add requires an explicit stewardship designation';
    END IF;
    IF designation_identity IS DISTINCT FROM actor_identity_id_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'acting Identity is not the designated steward acting Identity';
    END IF;

    -- 3. Actor Principal and Identity rows.
    SELECT i.principal_id INTO actor_principal
      FROM mtmf.identity AS i
      JOIN mtmf.principal AS p ON p.id = i.principal_id
     WHERE i.id = actor_identity_id_value
       AND i.deletion_status = 2
       AND p.deletion_status = 2
     FOR SHARE OF i, p;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add acting Identity is unknown, deleted, or deactivated';
    END IF;

    -- 4. Actor IdentityTenantMembership (blocks phantom grant inserts).
    PERFORM 1
      FROM mtmf.identity_tenant_membership
     WHERE identity_id = actor_identity_id_value
       AND tenant_id = tenant_id_value
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add acting Identity lacks same-Tenant membership';
    END IF;

    -- 5. Subject Identity row and same-Tenant membership.
    PERFORM 1
      FROM mtmf.identity
     WHERE id = subject_identity_id_value
       AND deletion_status = 2
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add subject Identity is unknown or deleted';
    END IF;
    PERFORM 1
      FROM mtmf.identity_tenant_membership
     WHERE identity_id = subject_identity_id_value
       AND tenant_id = tenant_id_value
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add subject Identity lacks same-Tenant membership';
    END IF;

    -- 6. Target Group row and same-Tenant membership.
    SELECT g.tenant_id INTO group_tenant
      FROM mtmf.group AS g
     WHERE g.id = group_id_value
       AND g.deletion_status = 2
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'membership-add target Group is unknown';
    END IF;
    IF group_tenant <> tenant_id_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add target Group belongs to another Tenant';
    END IF;
    PERFORM 1
      FROM mtmf.group_tenant_membership
     WHERE group_id = group_id_value
       AND tenant_id = tenant_id_value
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add target Group lacks same-Tenant membership';
    END IF;

    -- 7. Policy dependencies read by EffectiveRoleResolver. Locking the
    --    actor's existing memberships, assignments and referenced Role rows
    --    (in addition to the actor IdentityTenantMembership above) makes the
    --    subsequent exact-Action ALLOW stable: a concurrent grant insert
    --    blocks on the ITM FOR UPDATE, and a concurrent revocation or policy
    --    rewrite blocks on the FOR SHARE row locks.
    PERFORM 1
      FROM mtmf.identity_group_membership
     WHERE identity_id = actor_identity_id_value
     FOR SHARE;

    PERFORM 1
      FROM mtmf.identity_role_assignment
     WHERE tenant_id = tenant_id_value
       AND identity_id = actor_identity_id_value
     FOR SHARE;

    PERFORM 1
      FROM mtmf.group_role_assignment AS gra
     WHERE gra.tenant_id = tenant_id_value
       AND gra.group_id IN (
           SELECT igm.group_id
             FROM mtmf.identity_group_membership AS igm
            WHERE igm.identity_id = actor_identity_id_value
       )
     FOR SHARE;

    PERFORM 1
      FROM mtmf.role AS r
     WHERE r.urn IN (
         SELECT ira.role_urn
           FROM mtmf.identity_role_assignment AS ira
          WHERE ira.tenant_id = tenant_id_value
            AND ira.identity_id = actor_identity_id_value
     )
     FOR SHARE;

    PERFORM 1
      FROM mtmf.role AS r
     WHERE r.urn IN (
         SELECT gra.role_urn
           FROM mtmf.group_role_assignment AS gra
          WHERE gra.tenant_id = tenant_id_value
            AND gra.group_id IN (
                SELECT igm.group_id
                  FROM mtmf.identity_group_membership AS igm
                 WHERE igm.identity_id = actor_identity_id_value
            )
     )
     FOR SHARE;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_group_membership_add_verified(
    identity_id_value uuid,
    group_id_value uuid,
    operation_id_value uuid,
    actor_identity_id_value uuid,
    actor_principal_id_value uuid,
    tenant_id_value uuid,
    application_id_value uuid,
    action_urn_value text,
    target_kind_value text,
    target_id_value uuid,
    authorized_at_value timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    inserted boolean;
BEGIN
    IF identity_id_value IS NULL OR group_id_value IS NULL OR operation_id_value IS NULL
       OR actor_identity_id_value IS NULL OR actor_principal_id_value IS NULL
       OR tenant_id_value IS NULL OR application_id_value IS NULL
       OR action_urn_value IS NULL OR target_kind_value IS NULL
       OR target_id_value IS NULL OR authorized_at_value IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'membership-add provenance is incomplete';
    END IF;
    IF target_kind_value <> 'identity_group_membership' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'membership-add target kind is invalid';
    END IF;
    IF target_id_value <> group_id_value THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'membership-add target id is not the Group';
    END IF;
    IF action_urn_value <>
       'urn:mtmf:iam:actions:system:identity-group-membership:add-object' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'membership-add Action is not approved';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM mtmf.stewardship_designation AS d
         WHERE d.tenant_id = tenant_id_value
           AND d.designated_identity_id = actor_identity_id_value
           AND d.steward_principal_id = actor_principal_id_value
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'acting Identity is not the current designated steward';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM mtmf.identity AS i
          JOIN mtmf.identity_tenant_membership AS itm
            ON itm.identity_id = i.id AND itm.tenant_id = tenant_id_value
         WHERE i.id = identity_id_value
           AND i.deletion_status = 2
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add subject Identity is not eligible';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM mtmf.group AS g
          JOIN mtmf.group_tenant_membership AS gtm
            ON gtm.group_id = g.id AND gtm.tenant_id = tenant_id_value
         WHERE g.id = group_id_value
           AND g.tenant_id = tenant_id_value
           AND g.deletion_status = 2
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'membership-add target Group is not eligible';
    END IF;

    INSERT INTO mtmf.identity_group_membership (identity_id, group_id)
    VALUES (identity_id_value, group_id_value)
    ON CONFLICT DO NOTHING
    RETURNING true INTO STRICT inserted;

    -- The audit row is written iff a membership row was actually inserted,
    -- in the same statement/transaction. Any audit failure aborts the whole
    -- statement and marks the UnitOfWork rollback-only.
    INSERT INTO mtmf.security_mutation_audit (
        id,
        authorized_at,
        actor_identity_id,
        actor_principal_id,
        tenant_id,
        application_id,
        action_urn,
        target_kind,
        target_id,
        subject_identity_id,
        outcome
    ) VALUES (
        operation_id_value,
        authorized_at_value,
        actor_identity_id_value,
        actor_principal_id_value,
        tenant_id_value,
        application_id_value,
        action_urn_value,
        target_kind_value,
        target_id_value,
        identity_id_value,
        'CREATED'
    );
    RETURN true;
EXCEPTION
    WHEN no_data_found THEN
        -- The duplicate is a legitimate idempotent no-op: no audit row.
        RETURN false;
END;
$$;
