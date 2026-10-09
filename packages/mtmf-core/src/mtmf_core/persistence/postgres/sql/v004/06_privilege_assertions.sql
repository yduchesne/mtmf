-- v004: post-migration privilege assertions (defense in depth).
--
-- These checks run inside the migration transaction and fail it (rolling
-- back the function creation and grants) if the intended posture was not
-- achieved. The mandatory post-upgrade runtime verifier remains the
-- authoritative check; these assertions catch a defect as close to the
-- DDL as possible.

DO $$
DECLARE
    approved_count integer;
    offending integer;
BEGIN
    -- Exactly 50 approved runtime entry points: 6 membership-removal
    -- signatures plus the 44 repository functions.
    SELECT count(*)
      INTO approved_count
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF approved_count <> 50 THEN
        RAISE EXCEPTION
            'PRIV-7B assertion failed: runtime EXECUTE allowlist must be exactly 50 '
            'functions, found %', approved_count;
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
            'PRIV-7B assertion failed: % runtime entry point(s) are not owner-owned '
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
            'PRIV-7B assertion failed: PUBLIC retains EXECUTE on % mtmf function(s)',
            offending;
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
            'PRIV-7B assertion failed: runtime retains % table/sequence privilege(s)',
            offending;
    END IF;
END;
$$;
