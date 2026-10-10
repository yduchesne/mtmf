-- v009: TenantManagementGroup guards, privileged mutation, and runtime reads.
--
-- Privileged mutation functions are owner-owned, SECURITY INVOKER, pin
-- ``search_path = ''`` and are NEVER granted to mtmf_runtime. The runtime
-- read functions are narrowly reviewed SECURITY DEFINER entry points with a
-- fixed empty search_path; they return detached identifiers/JSON only.
--
-- Guard triggers enforce the structural invariants independently of the
-- application: ROOT manager must be the canonical root Tenant from a
-- completed bootstrap, SYSTEM manager must be an ordinary non-root Tenant,
-- ROOT membership rows and root targets are rejected, eligibility rows are
-- SYSTEM-only, and structural fields are immutable.

CREATE OR REPLACE FUNCTION mtmf.guard_tenant_management_group()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    manager_scope smallint;
    manager_deleted smallint;
    root_tenant uuid;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.manager_tenant_id IS DISTINCT FROM OLD.manager_tenant_id
           OR NEW.management_role_urn IS DISTINCT FROM OLD.management_role_urn
           OR NEW.scope IS DISTINCT FROM OLD.scope THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT030',
                MESSAGE = 'TenantManagementGroup structural fields are immutable';
        END IF;
    END IF;

    SELECT t.scope, t.deletion_status
      INTO manager_scope, manager_deleted
      FROM mtmf.tenant AS t
     WHERE t.id = NEW.manager_tenant_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT031',
            MESSAGE = 'TenantManagementGroup manager Tenant does not exist';
    END IF;
    IF manager_deleted <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT031',
            MESSAGE = 'TenantManagementGroup manager Tenant must not be soft-deleted';
    END IF;

    SELECT r.root_tenant_id INTO root_tenant
      FROM mtmf.root_registry AS r
     WHERE r.singleton;

    IF NEW.scope = 0 THEN
        IF root_tenant IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT032',
                MESSAGE = 'a ROOT TenantManagementGroup requires a completed root bootstrap';
        END IF;
        IF NEW.manager_tenant_id <> root_tenant THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT032',
                MESSAGE = 'a ROOT TenantManagementGroup must be managed by the canonical root Tenant';
        END IF;
        IF manager_scope <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT032',
                MESSAGE = 'a ROOT TenantManagementGroup manager Tenant must have ROOT scope';
        END IF;
    ELSE
        IF manager_scope <> 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT033',
                MESSAGE = 'a SYSTEM TenantManagementGroup manager Tenant must be an ordinary Tenant';
        END IF;
        IF root_tenant IS NOT NULL AND NEW.manager_tenant_id = root_tenant THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT033',
                MESSAGE = 'a SYSTEM TenantManagementGroup must not be managed by the canonical root Tenant';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.guard_tenant_management_group_membership()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    group_scope smallint;
    group_manager uuid;
    root_tenant uuid;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.management_group_id IS DISTINCT FROM OLD.management_group_id
           OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT030',
                MESSAGE = 'managed-Tenant relationship fields are immutable';
        END IF;
    END IF;

    SELECT g.scope, g.manager_tenant_id
      INTO group_scope, group_manager
      FROM mtmf.tenant_management_group AS g
     WHERE g.id = NEW.management_group_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT034',
            MESSAGE = 'managed-Tenant relationship references an unknown management group';
    END IF;
    IF group_scope <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT034',
            MESSAGE = 'a ROOT TenantManagementGroup must not contain explicit managed-Tenant rows';
    END IF;
    IF NEW.tenant_id = group_manager THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT034',
            MESSAGE = 'a TenantManagementGroup must not explicitly manage its own manager Tenant';
    END IF;

    SELECT r.root_tenant_id INTO root_tenant
      FROM mtmf.root_registry AS r
     WHERE r.singleton;
    IF root_tenant IS NOT NULL AND NEW.tenant_id = root_tenant THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT034',
            MESSAGE = 'the canonical root Tenant must not be an explicitly managed target';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM mtmf.tenant AS t
        WHERE t.id = NEW.tenant_id AND t.deletion_status = 2
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT034',
            MESSAGE = 'the managed Tenant must exist and not be soft-deleted';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.guard_tenant_management_group_actor_eligibility()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    group_scope smallint;
    group_manager uuid;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.management_group_id IS DISTINCT FROM OLD.management_group_id
           OR NEW.identity_id IS DISTINCT FROM OLD.identity_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT030',
                MESSAGE = 'eligibility designation fields are immutable';
        END IF;
    END IF;

    SELECT g.scope, g.manager_tenant_id
      INTO group_scope, group_manager
      FROM mtmf.tenant_management_group AS g
     WHERE g.id = NEW.management_group_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT035',
            MESSAGE = 'eligibility designation references an unknown management group';
    END IF;
    IF group_scope <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT035',
            MESSAGE = 'a ROOT TenantManagementGroup must not carry explicit eligibility designations';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.identity AS i
        WHERE i.id = NEW.identity_id AND i.deletion_status = 2
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT035',
            MESSAGE = 'an eligible Identity must exist and not be soft-deleted';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.identity_tenant_membership AS m
        WHERE m.identity_id = NEW.identity_id AND m.tenant_id = group_manager
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT035',
            MESSAGE = 'an eligible Identity must be a member of the manager Tenant';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenant_management_group_guard
    BEFORE INSERT OR UPDATE ON mtmf.tenant_management_group
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_tenant_management_group();

CREATE TRIGGER tenant_management_group_membership_guard
    BEFORE INSERT OR UPDATE ON mtmf.tenant_management_group_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_tenant_management_group_membership();

CREATE TRIGGER tenant_management_group_actor_eligibility_guard
    BEFORE INSERT OR UPDATE ON mtmf.tenant_management_group_actor_eligibility
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_tenant_management_group_actor_eligibility();

-- ROOT management group creation is atomic with the canonical root
-- registry: the AFTER INSERT trigger creates the single ROOT group in the
-- same bootstrap transaction. Root Identity recovery only replaces the
-- registry's root_identity_id, so ROOT eligibility follows the new root
-- Identity automatically with no stale authority.
CREATE OR REPLACE FUNCTION mtmf.create_root_management_group()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.tenant_management_group (
        id, manager_tenant_id, management_role_urn, scope
    )
    VALUES (
        gen_random_uuid(),
        NEW.root_tenant_id,
        'urn:mtmf:iam:roles:system:root-tenant-management',
        0
    )
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;

CREATE TRIGGER root_registry_management_group
    AFTER INSERT ON mtmf.root_registry
    FOR EACH ROW EXECUTE FUNCTION mtmf.create_root_management_group();

-- Installation/operator-only idempotent ROOT management group initialization
-- (safe for a database bootstrapped before v009, and for recovery).
CREATE OR REPLACE FUNCTION mtmf.initialize_root_tenant_management_group(id_value uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    root_tenant uuid;
    existing uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('mtmf.bootroot', 0));
    SELECT r.root_tenant_id INTO root_tenant
      FROM mtmf.root_registry AS r
     WHERE r.singleton;
    IF root_tenant IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT032',
            MESSAGE = 'ROOT management group initialization requires a completed root bootstrap';
    END IF;
    SELECT g.id INTO existing
      FROM mtmf.tenant_management_group AS g
     WHERE g.scope = 0;
    IF existing IS NOT NULL THEN
        RETURN existing;
    END IF;
    INSERT INTO mtmf.tenant_management_group (
        id, manager_tenant_id, management_role_urn, scope
    )
    VALUES (id_value, root_tenant, 'urn:mtmf:iam:roles:system:root-tenant-management', 0);
    RETURN id_value;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.create_tenant_management_group(
    id_value uuid,
    manager_tenant_id_value uuid,
    management_role_urn_value text,
    scope_value smallint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.tenant_management_group (
        id, manager_tenant_id, management_role_urn, scope
    )
    VALUES (id_value, manager_tenant_id_value, management_role_urn_value, scope_value)
    ON CONFLICT (id) DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.add_tenant_management_group_membership(
    id_value uuid,
    management_group_id_value uuid,
    tenant_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.tenant_management_group_membership (
        id, management_group_id, tenant_id
    )
    VALUES (id_value, management_group_id_value, tenant_id_value)
    ON CONFLICT (management_group_id, tenant_id) DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.remove_tenant_management_group_membership(
    management_group_id_value uuid,
    tenant_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    removed integer;
BEGIN
    DELETE FROM mtmf.tenant_management_group_membership
     WHERE management_group_id = management_group_id_value
       AND tenant_id = tenant_id_value;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed > 0;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.add_tenant_management_group_actor_eligibility(
    id_value uuid,
    management_group_id_value uuid,
    identity_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.tenant_management_group_actor_eligibility (
        id, management_group_id, identity_id
    )
    VALUES (id_value, management_group_id_value, identity_id_value)
    ON CONFLICT (management_group_id, identity_id) DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.remove_tenant_management_group_actor_eligibility(
    management_group_id_value uuid,
    identity_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    removed integer;
BEGIN
    DELETE FROM mtmf.tenant_management_group_actor_eligibility
     WHERE management_group_id = management_group_id_value
       AND identity_id = identity_id_value;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed > 0;
END;
$$;

-- Runtime read functions (narrowly reviewed, SECURITY DEFINER, fixed empty
-- search_path): authorization resolution only. They return detached
-- identifiers/JSON and never mutate state.

CREATE OR REPLACE FUNCTION mtmf.tenant_management_group_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', g.id,
        'manager_tenant_id', g.manager_tenant_id,
        'management_role_urn', g.management_role_urn,
        'scope', g.scope
    )
    FROM mtmf.tenant_management_group AS g
    WHERE g.id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_management_group_find_by_manager(
    manager_tenant_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', g.id,
        'manager_tenant_id', g.manager_tenant_id,
        'management_role_urn', g.management_role_urn,
        'scope', g.scope
    )
    FROM mtmf.tenant_management_group AS g
    WHERE g.manager_tenant_id = manager_tenant_id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_management_group_membership_get(
    management_group_id_value uuid,
    tenant_id_value uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', m.id,
        'management_group_id', m.management_group_id,
        'tenant_id', m.tenant_id
    )
    FROM mtmf.tenant_management_group_membership AS m
    WHERE m.management_group_id = management_group_id_value
      AND m.tenant_id = tenant_id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_management_group_membership_find_by_group(
    management_group_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', m.id,
        'management_group_id', m.management_group_id,
        'tenant_id', m.tenant_id
    )
    FROM mtmf.tenant_management_group_membership AS m
    WHERE m.management_group_id = management_group_id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_management_group_membership_find_by_tenant(
    tenant_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', m.id,
        'management_group_id', m.management_group_id,
        'tenant_id', m.tenant_id
    )
    FROM mtmf.tenant_management_group_membership AS m
    WHERE m.tenant_id = tenant_id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_management_group_actor_eligibility_get(
    management_group_id_value uuid,
    identity_id_value uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', e.id,
        'management_group_id', e.management_group_id,
        'identity_id', e.identity_id
    )
    FROM mtmf.tenant_management_group_actor_eligibility AS e
    WHERE e.management_group_id = management_group_id_value
      AND e.identity_id = identity_id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_group(
    management_group_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', e.id,
        'management_group_id', e.management_group_id,
        'identity_id', e.identity_id
    )
    FROM mtmf.tenant_management_group_actor_eligibility AS e
    WHERE e.management_group_id = management_group_id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_identity(
    identity_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', e.id,
        'management_group_id', e.management_group_id,
        'identity_id', e.identity_id
    )
    FROM mtmf.tenant_management_group_actor_eligibility AS e
    WHERE e.identity_id = identity_id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.root_registry_get()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'root_tenant_id', r.root_tenant_id,
        'root_principal_id', r.root_principal_id,
        'root_identity_id', r.root_identity_id
    )
    FROM mtmf.root_registry AS r
    WHERE r.singleton;
$$;

-- Backfill a ROOT management group for databases bootstrapped before v009.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM mtmf.root_registry WHERE singleton)
       AND NOT EXISTS (SELECT 1 FROM mtmf.tenant_management_group WHERE scope = 0) THEN
        PERFORM mtmf.initialize_root_tenant_management_group(gen_random_uuid());
    END IF;
END;
$$;
