-- v008: post-migration assertions (defense in depth).

DO $$
DECLARE
    missing_tables integer;
    privileged_executable integer;
BEGIN
    SELECT count(*)
      INTO missing_tables
      FROM (VALUES ('root_registry'), ('stewardship_designation'), ('stewardship_audit')) AS t(name)
     WHERE NOT EXISTS (
         SELECT 1 FROM information_schema.tables
          WHERE table_schema = 'mtmf' AND table_name = t.name
     );
    IF missing_tables <> 0 THEN
        RAISE EXCEPTION
            'v008 assertion failed: root/stewardship tables are missing';
    END IF;

    SELECT count(*)
      INTO privileged_executable
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'bootstrap_root', 'designate_steward', 'activate_tenant',
           'suspend_tenant', 'recover_root_identity', 'stewardship_is_eligible'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF privileged_executable <> 0 THEN
        RAISE EXCEPTION
            'v008 assertion failed: mtmf_runtime must not EXECUTE privileged root/stewardship functions (found %)',
            privileged_executable;
    END IF;

    IF has_function_privilege('mtmf_runtime', 'mtmf.bootstrap_root(uuid, uuid, uuid, text, text, text)', 'EXECUTE') THEN
        RAISE EXCEPTION 'v008 assertion failed: mtmf_runtime can EXECUTE bootstrap_root';
    END IF;
END;
$$;
