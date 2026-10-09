-- v005: post-migration privilege assertions (defense in depth).
--
-- These checks run inside the migration transaction and fail it (rolling
-- back the assignment tables, functions, and grants) if the intended
-- posture was not achieved. The mandatory post-upgrade runtime verifier
-- (which compares the exact signature manifest) remains authoritative;
-- these assertions catch a defect as close to the DDL as possible.
--
-- The reviewed inventory through v005 is the 50 approved entry points
-- through v004 plus the 8 new Role-assignment entry points (an explicit
-- reviewed sum, not a stale hardcoded figure).

DO $$
DECLARE
    approved_count integer;
    offending integer;
    new_entry_points integer;
BEGIN
    -- Exactly 58 approved runtime entry points: 50 through revision 0004
    -- plus the 8 Role-assignment functions granted in 03.
    SELECT count(*)
      INTO approved_count
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF approved_count <> 58 THEN
        RAISE EXCEPTION
            'PRIV-9 assertion failed: runtime EXECUTE allowlist must be exactly 58 '
            'functions (50 through v004 plus 8 role-assignment entry points), found %',
            approved_count;
    END IF;

    -- The 8 new entry points are runtime-executable.
    SELECT count(*)
      INTO new_entry_points
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'identity_role_assignment_add',
           'identity_role_assignment_get',
           'identity_role_assignment_find_by_tenant_and_identity',
           'identity_role_assignment_remove',
           'group_role_assignment_add',
           'group_role_assignment_get',
           'group_role_assignment_find_by_tenant_and_group',
           'group_role_assignment_remove'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF new_entry_points <> 8 THEN
        RAISE EXCEPTION
            'PRIV-9 assertion failed: expected 8 runtime-granted role-assignment '
            'functions, found %', new_entry_points;
    END IF;

    -- The three private validation helpers are NOT runtime-executable.
    SELECT count(*)
      INTO offending
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'role_assignment_validate_role',
           'identity_role_assignment_validate',
           'group_role_assignment_validate'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF offending <> 0 THEN
        RAISE EXCEPTION
            'PRIV-9 assertion failed: % role-assignment validation helper(s) are '
            'runtime-executable', offending;
    END IF;

    -- Every approved runtime entry point is owner-owned SECURITY DEFINER
    -- with a fixed empty search_path.
    SELECT count(*)
      INTO offending
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')
       AND (
           NOT p.prosecdef
           OR pg_get_userbyid(p.proowner) <> 'mtmf_owner'
           OR NOT (p.proconfig @> ARRAY['search_path=""'])
       );
    IF offending <> 0 THEN
        RAISE EXCEPTION
            'PRIV-9 assertion failed: % runtime entry point(s) are not owner-owned '
            'SECURITY DEFINER functions with search_path pinned', offending;
    END IF;

    -- PUBLIC holds no EXECUTE on any mtmf function.
    SELECT count(*)
      INTO offending
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND EXISTS (
           SELECT 1
             FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) AS a
            WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'
       );
    IF offending <> 0 THEN
        RAISE EXCEPTION
            'PRIV-9 assertion failed: PUBLIC retains EXECUTE on % mtmf function(s)',
            offending;
    END IF;

    -- All functions created by v005 have a fixed empty search_path,
    -- including the private helpers.
    SELECT count(*)
      INTO offending
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'role_assignment_validate_role',
           'identity_role_assignment_validate',
           'group_role_assignment_validate',
           'identity_role_assignment_add',
           'identity_role_assignment_get',
           'identity_role_assignment_find_by_tenant_and_identity',
           'identity_role_assignment_remove',
           'group_role_assignment_add',
           'group_role_assignment_get',
           'group_role_assignment_find_by_tenant_and_group',
           'group_role_assignment_remove'
       )
       AND (
           pg_get_userbyid(p.proowner) <> 'mtmf_owner'
           OR NOT (p.proconfig @> ARRAY['search_path=""'])
       );
    IF offending <> 0 THEN
        RAISE EXCEPTION
            'PRIV-9 assertion failed: % v005 function(s) are not owner-owned with '
            'search_path pinned', offending;
    END IF;

    -- The runtime still holds no table or sequence privilege.
    SELECT count(*)
      INTO offending
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'mtmf'
       AND (
           (c.relkind IN ('r', 'p', 'v', 'm') AND (
               has_table_privilege('mtmf_runtime', c.oid, 'SELECT')
               OR has_table_privilege('mtmf_runtime', c.oid, 'INSERT')
               OR has_table_privilege('mtmf_runtime', c.oid, 'UPDATE')
               OR has_table_privilege('mtmf_runtime', c.oid, 'DELETE')
               OR has_table_privilege('mtmf_runtime', c.oid, 'TRUNCATE')
               OR has_table_privilege('mtmf_runtime', c.oid, 'REFERENCES')
               OR has_table_privilege('mtmf_runtime', c.oid, 'TRIGGER')
           ))
           OR (c.relkind = 'S' AND (
               has_sequence_privilege('mtmf_runtime', c.oid, 'USAGE')
               OR has_sequence_privilege('mtmf_runtime', c.oid, 'SELECT')
               OR has_sequence_privilege('mtmf_runtime', c.oid, 'UPDATE')
           ))
       );
    IF offending <> 0 THEN
        RAISE EXCEPTION
            'PRIV-9 assertion failed: runtime retains % table/sequence privilege(s)',
            offending;
    END IF;
END;
$$;
