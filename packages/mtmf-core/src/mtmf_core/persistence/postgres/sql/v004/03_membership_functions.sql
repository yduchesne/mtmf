-- v004: typed membership repository functions.
--
-- Six explicit typed relationships, no polymorphic member identity and no
-- generic delete. Each repository operation is one function:
--
--   *_add   -> INSERT ... ON CONFLICT DO NOTHING; returns false on a
--              duplicate relationship and never turns an invalid insert
--              into a silent no-op. A prerequisite failure raised by the
--              v001/v002 BEFORE INSERT trigger (P0001) is re-raised as the
--              reviewed custom code MT002 rather than leaked as a
--              generic plpgsql error.
--   *_get   -> returns whether the exact relationship fact exists.
--   *_find_* -> returns the opposite participant UUID for every matching
--              fact, ordered by that UUID, so callers receive a
--              deterministic detached sequence.

CREATE OR REPLACE FUNCTION mtmf.principal_tenant_membership_add(
    principal_id_value uuid,
    tenant_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.principal_tenant_membership (principal_id, tenant_id)
    VALUES (principal_id_value, tenant_id_value)
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
EXCEPTION WHEN raise_exception THEN
    RAISE EXCEPTION USING
        ERRCODE = 'MT002',
        MESSAGE = 'membership prerequisite is absent or structurally invalid';
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.principal_tenant_membership_get(
    principal_id_value uuid,
    tenant_id_value uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM mtmf.principal_tenant_membership
        WHERE principal_id = principal_id_value
          AND tenant_id = tenant_id_value
    );
$$;

CREATE OR REPLACE FUNCTION mtmf.principal_tenant_membership_find_by_principal(
    principal_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT tenant_id
    FROM mtmf.principal_tenant_membership
    WHERE principal_id = principal_id_value
    ORDER BY tenant_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.principal_tenant_membership_find_by_tenant(
    tenant_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT principal_id
    FROM mtmf.principal_tenant_membership
    WHERE tenant_id = tenant_id_value
    ORDER BY principal_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_tenant_membership_add(
    identity_id_value uuid,
    tenant_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id)
    VALUES (identity_id_value, tenant_id_value)
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
EXCEPTION WHEN raise_exception THEN
    RAISE EXCEPTION USING
        ERRCODE = 'MT002',
        MESSAGE = 'membership prerequisite is absent or structurally invalid';
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_tenant_membership_get(
    identity_id_value uuid,
    tenant_id_value uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM mtmf.identity_tenant_membership
        WHERE identity_id = identity_id_value
          AND tenant_id = tenant_id_value
    );
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_tenant_membership_find_by_identity(
    identity_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT tenant_id
    FROM mtmf.identity_tenant_membership
    WHERE identity_id = identity_id_value
    ORDER BY tenant_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_tenant_membership_find_by_tenant(
    tenant_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT identity_id
    FROM mtmf.identity_tenant_membership
    WHERE tenant_id = tenant_id_value
    ORDER BY identity_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_tenant_membership_add(
    group_id_value uuid,
    tenant_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.group_tenant_membership (group_id, tenant_id)
    VALUES (group_id_value, tenant_id_value)
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
EXCEPTION WHEN raise_exception THEN
    RAISE EXCEPTION USING
        ERRCODE = 'MT002',
        MESSAGE = 'membership prerequisite is absent or structurally invalid';
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_tenant_membership_get(
    group_id_value uuid,
    tenant_id_value uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM mtmf.group_tenant_membership
        WHERE group_id = group_id_value
          AND tenant_id = tenant_id_value
    );
$$;

CREATE OR REPLACE FUNCTION mtmf.group_tenant_membership_find_by_group(
    group_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT tenant_id
    FROM mtmf.group_tenant_membership
    WHERE group_id = group_id_value
    ORDER BY tenant_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_tenant_membership_find_by_tenant(
    tenant_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT group_id
    FROM mtmf.group_tenant_membership
    WHERE tenant_id = tenant_id_value
    ORDER BY group_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_group_membership_add(
    identity_id_value uuid,
    group_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.identity_group_membership (identity_id, group_id)
    VALUES (identity_id_value, group_id_value)
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
EXCEPTION WHEN raise_exception THEN
    RAISE EXCEPTION USING
        ERRCODE = 'MT002',
        MESSAGE = 'membership prerequisite is absent or structurally invalid';
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_group_membership_get(
    identity_id_value uuid,
    group_id_value uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM mtmf.identity_group_membership
        WHERE identity_id = identity_id_value
          AND group_id = group_id_value
    );
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_group_membership_find_by_identity(
    identity_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT group_id
    FROM mtmf.identity_group_membership
    WHERE identity_id = identity_id_value
    ORDER BY group_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_group_membership_find_by_group(
    group_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT identity_id
    FROM mtmf.identity_group_membership
    WHERE group_id = group_id_value
    ORDER BY identity_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_org_membership_add(
    identity_id_value uuid,
    organization_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.identity_org_membership (identity_id, organization_id)
    VALUES (identity_id_value, organization_id_value)
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
EXCEPTION WHEN raise_exception THEN
    RAISE EXCEPTION USING
        ERRCODE = 'MT002',
        MESSAGE = 'membership prerequisite is absent or structurally invalid';
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_org_membership_get(
    identity_id_value uuid,
    organization_id_value uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM mtmf.identity_org_membership
        WHERE identity_id = identity_id_value
          AND organization_id = organization_id_value
    );
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_org_membership_find_by_identity(
    identity_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT organization_id
    FROM mtmf.identity_org_membership
    WHERE identity_id = identity_id_value
    ORDER BY organization_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_org_membership_find_by_organization(
    organization_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT identity_id
    FROM mtmf.identity_org_membership
    WHERE organization_id = organization_id_value
    ORDER BY identity_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_org_membership_add(
    group_id_value uuid,
    organization_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.group_org_membership (group_id, organization_id)
    VALUES (group_id_value, organization_id_value)
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
EXCEPTION WHEN raise_exception THEN
    RAISE EXCEPTION USING
        ERRCODE = 'MT002',
        MESSAGE = 'membership prerequisite is absent or structurally invalid';
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_org_membership_get(
    group_id_value uuid,
    organization_id_value uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM mtmf.group_org_membership
        WHERE group_id = group_id_value
          AND organization_id = organization_id_value
    );
$$;

CREATE OR REPLACE FUNCTION mtmf.group_org_membership_find_by_group(
    group_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT organization_id
    FROM mtmf.group_org_membership
    WHERE group_id = group_id_value
    ORDER BY organization_id;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_org_membership_find_by_organization(
    organization_id_value uuid
)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT group_id
    FROM mtmf.group_org_membership
    WHERE organization_id = organization_id_value
    ORDER BY group_id;
$$;
