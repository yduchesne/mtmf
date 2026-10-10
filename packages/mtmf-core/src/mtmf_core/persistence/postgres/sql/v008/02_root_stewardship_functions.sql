-- v008: installation-only root bootstrap, stewardship designation, and
-- lifecycle activation/recovery primitives.
--
-- Every function is owner-owned, SECURITY INVOKER (it runs only in the
-- owner/migrator installation context), pins an empty search_path, and is
-- NEVER granted to mtmf_runtime. An ``actor_provenance`` argument is a data
-- value for audit only; it is not authentication and not authorization.

-- Structural eligibility: ordinary Tenant + active Principal/Identity +
-- explicit memberships + an effective Tenant Administrator Role (direct or
-- group-derived, Tenant-wide). This is the DB-side structural predicate;
-- the trusted application layer remains responsible for authenticating the
-- acting Identity.
CREATE OR REPLACE FUNCTION mtmf.stewardship_is_eligible(
    tenant_id_value uuid,
    principal_id_value uuid,
    identity_id_value uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = ''
AS $$
    SELECT
        EXISTS (
            SELECT 1 FROM mtmf.tenant t
            WHERE t.id = tenant_id_value AND t.scope = 2 AND t.deletion_status = 2
        )
        AND EXISTS (
            SELECT 1 FROM mtmf.principal p
            WHERE p.id = principal_id_value AND p.deletion_status = 2
        )
        AND EXISTS (
            SELECT 1 FROM mtmf.identity i
            WHERE i.id = identity_id_value
              AND i.principal_id = principal_id_value
              AND i.deletion_status = 2
        )
        AND EXISTS (
            SELECT 1 FROM mtmf.principal_tenant_membership m
            WHERE m.principal_id = principal_id_value AND m.tenant_id = tenant_id_value
        )
        AND EXISTS (
            SELECT 1 FROM mtmf.identity_tenant_membership m
            WHERE m.identity_id = identity_id_value AND m.tenant_id = tenant_id_value
        )
        AND (
            EXISTS (
                SELECT 1 FROM mtmf.identity_role_assignment ira
                WHERE ira.tenant_id = tenant_id_value
                  AND ira.identity_id = identity_id_value
                  AND ira.role_urn = 'urn:mtmf:iam:roles:system:tenant-administrator'
                  AND ira.organization_id IS NULL
            )
            OR EXISTS (
                SELECT 1 FROM mtmf.identity_group_membership igm
                JOIN mtmf.group_role_assignment gra
                  ON gra.group_id = igm.group_id AND gra.tenant_id = tenant_id_value
                WHERE igm.identity_id = identity_id_value
                  AND gra.role_urn = 'urn:mtmf:iam:roles:system:tenant-administrator'
                  AND gra.organization_id IS NULL
            )
        );
$$;

CREATE OR REPLACE FUNCTION mtmf.bootstrap_root(
    root_tenant_id_value uuid,
    root_principal_id_value uuid,
    root_identity_id_value uuid,
    root_tenant_name_value text,
    root_principal_name_value text,
    root_identity_name_value text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    existing record;
BEGIN
    -- Serialize concurrent bootstrap attempts on a fixed advisory key.
    PERFORM pg_advisory_xact_lock(hashtextextended('mtmf.bootroot', 0));

    SELECT * INTO existing FROM mtmf.root_registry WHERE singleton;
    IF FOUND THEN
        IF existing.root_tenant_id = root_tenant_id_value
           AND existing.root_principal_id = root_principal_id_value
           AND existing.root_identity_id = root_identity_id_value THEN
            RETURN jsonb_build_object(
                'root_tenant_id', existing.root_tenant_id,
                'root_principal_id', existing.root_principal_id,
                'root_identity_id', existing.root_identity_id,
                'bootstrap_version', existing.bootstrap_version
            );
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = 'MT020',
            MESSAGE = 'root bootstrap registry conflicts with the supplied canonical IDs';
    END IF;

    IF EXISTS (SELECT 1 FROM mtmf.tenant WHERE id = root_tenant_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.principal WHERE id = root_principal_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.identity WHERE id = root_identity_id_value) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT021',
            MESSAGE = 'root bootstrap found pre-existing canonical objects and will not repair them';
    END IF;

    INSERT INTO mtmf.principal (id, name, deletion_status)
    VALUES (root_principal_id_value, root_principal_name_value, 2);

    INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status)
    VALUES (root_identity_id_value, root_principal_id_value, root_identity_name_value, 1, 2);

    -- Root Tenant: ROOT scope, ACTIVE, owned by the designated root Identity.
    INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status)
    VALUES (root_tenant_id_value, root_tenant_name_value, 0, root_identity_id_value, 1, 2);

    INSERT INTO mtmf.principal_tenant_membership (principal_id, tenant_id)
    VALUES (root_principal_id_value, root_tenant_id_value);

    INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id)
    VALUES (root_identity_id_value, root_tenant_id_value);

    INSERT INTO mtmf.root_registry (
        singleton, root_tenant_id, root_principal_id, root_identity_id, bootstrap_version
    )
    VALUES (true, root_tenant_id_value, root_principal_id_value, root_identity_id_value, 1);

    INSERT INTO mtmf.stewardship_audit (
        tenant_id, operation, new_principal_id, new_identity_id, reason
    )
    VALUES (
        root_tenant_id_value, 'BOOTSTRAP', root_principal_id_value,
        root_identity_id_value, 'initial root bootstrap'
    );

    RETURN jsonb_build_object(
        'root_tenant_id', root_tenant_id_value,
        'root_principal_id', root_principal_id_value,
        'root_identity_id', root_identity_id_value,
        'bootstrap_version', 1
    );
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.designate_steward(
    tenant_id_value uuid,
    steward_principal_id_value uuid,
    designated_identity_id_value uuid,
    expected_version_value integer,
    operation_value text,
    reason_value text,
    actor_provenance_value text
)
RETURNS integer
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    has_existing boolean;
    previous_principal uuid;
    previous_identity uuid;
    new_version integer;
BEGIN
    IF operation_value NOT IN ('TRANSFER', 'RECOVERY') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT022',
            MESSAGE = 'designate_steward operation must be TRANSFER or RECOVERY';
    END IF;

    -- Global lock order: Tenant, then successor Principal/Identity, then the
    -- designation row. Locking the subject rows prevents a concurrent
    -- deactivation from committing after the eligibility read (write skew).
    PERFORM 1 FROM mtmf.tenant WHERE id = tenant_id_value FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT023',
            MESSAGE = 'designate_steward target Tenant does not exist';
    END IF;
    PERFORM 1 FROM mtmf.principal WHERE id = steward_principal_id_value FOR UPDATE;
    PERFORM 1 FROM mtmf.identity WHERE id = designated_identity_id_value FOR UPDATE;

    SELECT d.steward_principal_id, d.designated_identity_id
      INTO previous_principal, previous_identity
      FROM mtmf.stewardship_designation d
     WHERE d.tenant_id = tenant_id_value
     FOR UPDATE;
    has_existing := FOUND;

    IF has_existing AND expected_version_value IS NOT NULL
       AND (SELECT version FROM mtmf.stewardship_designation WHERE tenant_id = tenant_id_value)
           IS DISTINCT FROM expected_version_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT012',
            MESSAGE = 'stewardship designation version is stale';
    ELSIF NOT has_existing AND expected_version_value IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT012',
            MESSAGE = 'stewardship designation does not exist at the expected version';
    END IF;

    IF NOT mtmf.stewardship_is_eligible(
        tenant_id_value, steward_principal_id_value, designated_identity_id_value
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT013',
            MESSAGE = 'proposed steward Principal/acting Identity is not eligible';
    END IF;

    IF has_existing THEN
        SELECT version + 1 INTO new_version
        FROM mtmf.stewardship_designation WHERE tenant_id = tenant_id_value;
        UPDATE mtmf.stewardship_designation
           SET steward_principal_id = steward_principal_id_value,
               designated_identity_id = designated_identity_id_value,
               version = new_version
         WHERE tenant_id = tenant_id_value;
    ELSE
        new_version := 1;
        previous_principal := NULL;
        previous_identity := NULL;
        INSERT INTO mtmf.stewardship_designation (
            tenant_id, steward_principal_id, designated_identity_id, version
        )
        VALUES (
            tenant_id_value, steward_principal_id_value, designated_identity_id_value, new_version
        );
    END IF;

    INSERT INTO mtmf.stewardship_audit (
        tenant_id, operation, previous_principal_id, new_principal_id,
        previous_identity_id, new_identity_id, actor_provenance, reason
    )
    VALUES (
        tenant_id_value, operation_value, previous_principal, steward_principal_id_value,
        previous_identity, designated_identity_id_value, actor_provenance_value, reason_value
    );

    RETURN new_version;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.activate_tenant(tenant_id_value uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    tenant_row record;
    designation_row record;
BEGIN
    SELECT * INTO tenant_row FROM mtmf.tenant WHERE id = tenant_id_value FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT023', MESSAGE = 'activation target Tenant does not exist';
    END IF;
    IF tenant_row.scope <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT024',
            MESSAGE = 'only ordinary Tenants may be activated through this operation';
    END IF;

    SELECT * INTO designation_row
      FROM mtmf.stewardship_designation WHERE tenant_id = tenant_id_value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT014',
            MESSAGE = 'cannot activate an ordinary Tenant without a stewardship designation';
    END IF;
    -- Lock the designated subject rows before the eligibility read so a
    -- concurrent deactivation cannot slip past it before this commits.
    PERFORM 1 FROM mtmf.principal WHERE id = designation_row.steward_principal_id FOR UPDATE;
    PERFORM 1 FROM mtmf.identity WHERE id = designation_row.designated_identity_id FOR UPDATE;
    IF NOT mtmf.stewardship_is_eligible(
        tenant_id_value, designation_row.steward_principal_id, designation_row.designated_identity_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT013',
            MESSAGE = 'the designated steward is no longer eligible';
    END IF;

    UPDATE mtmf.tenant SET lifecycle = 1 WHERE id = tenant_id_value;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.suspend_tenant(tenant_id_value uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    PERFORM 1 FROM mtmf.tenant WHERE id = tenant_id_value AND scope = 2 FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT024',
            MESSAGE = 'only an existing ordinary Tenant may be suspended';
    END IF;
    UPDATE mtmf.tenant SET lifecycle = 2 WHERE id = tenant_id_value;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.recover_root_identity(
    new_identity_id_value uuid,
    reason_value text,
    actor_provenance_value text
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    registry record;
    candidate record;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('mtmf.bootroot', 0));

    SELECT * INTO registry FROM mtmf.root_registry WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT025',
            MESSAGE = 'root identity recovery requires a completed bootstrap';
    END IF;

    SELECT * INTO candidate
      FROM mtmf.identity WHERE id = new_identity_id_value FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT026', MESSAGE = 'replacement root Identity does not exist';
    END IF;
    IF candidate.principal_id <> registry.root_principal_id THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT026',
            MESSAGE = 'replacement root Identity must belong to the canonical root Principal';
    END IF;
    IF candidate.origin <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT027',
            MESSAGE = 'replacement root Identity must be LOCAL';
    END IF;
    IF candidate.deletion_status <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT026',
            MESSAGE = 'replacement root Identity must not be soft-deleted';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.identity_tenant_membership m
        WHERE m.identity_id = new_identity_id_value AND m.tenant_id = registry.root_tenant_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT026',
            MESSAGE = 'replacement root Identity requires a root-Tenant membership';
    END IF;

    UPDATE mtmf.root_registry SET root_identity_id = new_identity_id_value WHERE singleton;

    -- The root Principal is unchanged; the audit records it in both the
    -- previous/new Principal columns (which are NOT NULL for new).
    INSERT INTO mtmf.stewardship_audit (
        tenant_id, operation, previous_principal_id, new_principal_id,
        previous_identity_id, new_identity_id, actor_provenance, reason
    )
    VALUES (
        registry.root_tenant_id, 'ROOT_IDENTITY_RECOVERY',
        registry.root_principal_id, registry.root_principal_id,
        registry.root_identity_id, new_identity_id_value,
        actor_provenance_value, reason_value
    );
END;
$$;
