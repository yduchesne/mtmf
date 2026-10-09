-- v005: trusted repository functions for typed Role assignments.
--
-- Every operation is a single reviewed function. Reads return detached
-- JSON objects (or a set of them); the runtime never touches the tables
-- directly. The three validation helpers are owner-owned but are NOT
-- runtime-granted (see 03); only the SECURITY DEFINER entry points call
-- them.
--
-- Contract per operation:
--   *_add   -> validate Tenant/subject/Role/Organization prerequisites,
--              then INSERT ... ON CONFLICT DO NOTHING; returns false when
--              the surrogate identity or the logical assignment tuple
--              already exists (committed or staged), never raising for a
--              plain duplicate.
--   *_get   -> returns one detached JSON object, or SQL NULL when absent.
--   *_find_*-> returns detached JSON objects ordered deterministically.
--   *_remove-> physically deletes exactly the addressed assignment and
--              returns false when it is unknown; there is no tombstone.
--
-- Prerequisite locks (``FOR KEY SHARE``) serialize an assignment insert
-- against the ``FOR UPDATE`` lock taken by the v002 membership-removal
-- functions, so a concurrent prerequisite removal cannot let an orphan or
-- cross-Tenant grant commit. The composite foreign keys are the ultimate
-- backstop and reject any stale reference at insert time.

CREATE OR REPLACE FUNCTION mtmf.role_assignment_validate_role(
    role_urn_value text,
    tenant_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    role_tenant uuid;
BEGIN
    SELECT defining_tenant_id INTO role_tenant
      FROM mtmf.role
     WHERE urn = role_urn_value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'role assignment references an unknown Role';
    END IF;
    IF role_tenant IS NOT NULL AND role_tenant <> tenant_id_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT004',
            MESSAGE = 'a TENANT-defined Role may only be assigned within its defining Tenant';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_role_assignment_validate(
    tenant_id_value uuid,
    identity_id_value uuid,
    role_urn_value text,
    organization_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    locked boolean;
BEGIN
    SELECT true INTO locked
      FROM mtmf.identity_tenant_membership
     WHERE identity_id = identity_id_value
       AND tenant_id = tenant_id_value
       FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'identity role assignment requires an IdentityTenantMembership '
                      'in the assignment Tenant';
    END IF;

    PERFORM mtmf.role_assignment_validate_role(role_urn_value, tenant_id_value);

    IF organization_id_value IS NOT NULL THEN
        SELECT true INTO locked
          FROM mtmf.organization
         WHERE id = organization_id_value
           AND tenant_id = tenant_id_value
           FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT001',
                MESSAGE = 'identity role assignment Organization does not belong '
                          'to the assignment Tenant';
        END IF;

        SELECT true INTO locked
          FROM mtmf.identity_org_membership
         WHERE identity_id = identity_id_value
           AND organization_id = organization_id_value
           FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT002',
                MESSAGE = 'identity role assignment requires an IdentityOrgMembership '
                          'for the Organization';
        END IF;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_role_assignment_validate(
    tenant_id_value uuid,
    group_id_value uuid,
    role_urn_value text,
    organization_id_value uuid
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    locked boolean;
    group_tenant uuid;
BEGIN
    SELECT tenant_id INTO group_tenant
      FROM mtmf.group
     WHERE id = group_id_value;
    IF group_tenant IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'group role assignment references an unknown Group';
    END IF;
    IF group_tenant <> tenant_id_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT004',
            MESSAGE = 'group role assignment Tenant disagrees with the Group structural Tenant';
    END IF;

    SELECT true INTO locked
      FROM mtmf.group_tenant_membership
     WHERE group_id = group_id_value
       AND tenant_id = tenant_id_value
       FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT002',
            MESSAGE = 'group role assignment requires a GroupTenantMembership '
                      'in the assignment Tenant';
    END IF;

    PERFORM mtmf.role_assignment_validate_role(role_urn_value, tenant_id_value);

    IF organization_id_value IS NOT NULL THEN
        SELECT true INTO locked
          FROM mtmf.organization
         WHERE id = organization_id_value
           AND tenant_id = tenant_id_value
           FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT001',
                MESSAGE = 'group role assignment Organization does not belong '
                          'to the assignment Tenant';
        END IF;

        SELECT true INTO locked
          FROM mtmf.group_org_membership
         WHERE group_id = group_id_value
           AND organization_id = organization_id_value
           FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT002',
                MESSAGE = 'group role assignment requires a GroupOrgMembership '
                          'for the Organization';
        END IF;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_role_assignment_add(
    id_value uuid,
    tenant_id_value uuid,
    identity_id_value uuid,
    role_urn_value text,
    organization_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    PERFORM mtmf.identity_role_assignment_validate(
        tenant_id_value, identity_id_value, role_urn_value, organization_id_value
    );
    INSERT INTO mtmf.identity_role_assignment (
        id, tenant_id, identity_id, role_urn, organization_id
    ) VALUES (
        id_value, tenant_id_value, identity_id_value, role_urn_value, organization_id_value
    )
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_role_assignment_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'tenant_id', tenant_id,
        'identity_id', identity_id,
        'role_urn', role_urn,
        'organization_id', organization_id
    )
    FROM mtmf.identity_role_assignment
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_role_assignment_find_by_tenant_and_identity(
    tenant_id_value uuid,
    identity_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'tenant_id', tenant_id,
        'identity_id', identity_id,
        'role_urn', role_urn,
        'organization_id', organization_id
    )
    FROM mtmf.identity_role_assignment
    WHERE tenant_id = tenant_id_value
      AND identity_id = identity_id_value
    ORDER BY role_urn, organization_id NULLS FIRST, id;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_role_assignment_remove(id_value uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    DELETE FROM mtmf.identity_role_assignment
     WHERE id = id_value;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_role_assignment_add(
    id_value uuid,
    tenant_id_value uuid,
    group_id_value uuid,
    role_urn_value text,
    organization_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    PERFORM mtmf.group_role_assignment_validate(
        tenant_id_value, group_id_value, role_urn_value, organization_id_value
    );
    INSERT INTO mtmf.group_role_assignment (
        id, tenant_id, group_id, role_urn, organization_id
    ) VALUES (
        id_value, tenant_id_value, group_id_value, role_urn_value, organization_id_value
    )
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_role_assignment_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'tenant_id', tenant_id,
        'group_id', group_id,
        'role_urn', role_urn,
        'organization_id', organization_id
    )
    FROM mtmf.group_role_assignment
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_role_assignment_find_by_tenant_and_group(
    tenant_id_value uuid,
    group_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'tenant_id', tenant_id,
        'group_id', group_id,
        'role_urn', role_urn,
        'organization_id', organization_id
    )
    FROM mtmf.group_role_assignment
    WHERE tenant_id = tenant_id_value
      AND group_id = group_id_value
    ORDER BY role_urn, organization_id NULLS FIRST, id;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_role_assignment_remove(id_value uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    DELETE FROM mtmf.group_role_assignment
     WHERE id = id_value;
    RETURN FOUND;
END;
$$;
