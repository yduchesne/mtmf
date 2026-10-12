-- v011: post-migration assertions (defense in depth).
--
-- The mandatory post-upgrade runtime verifier (exact signature manifest)
-- remains authoritative.

DO $$
DECLARE
    missing_tables integer;
    public_can_execute integer;
    approved_count integer;
    new_entry_points integer;
    runtime_table_privileges integer;
BEGIN
    SELECT count(*)
      INTO missing_tables
      FROM (VALUES
          ('service_credential_application'),
          ('external_subject_identity')
      ) AS t(name)
     WHERE NOT EXISTS (
         SELECT 1 FROM information_schema.tables
          WHERE table_schema = 'mtmf' AND table_name = t.name
     );
    IF missing_tables <> 0 THEN
        RAISE EXCEPTION 'v011 assertion failed: authentication binding tables are missing';
    END IF;

    -- Exactly 77 approved runtime entry points: the 75 through v010 plus the
    -- two authentication binding reads granted in 03.
    SELECT count(*)
      INTO approved_count
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF approved_count <> 77 THEN
        RAISE EXCEPTION
            'v011 assertion failed: runtime EXECUTE allowlist must be exactly 77 '
            'functions (75 through v010 plus 2 authentication binding reads), found %',
            approved_count;
    END IF;

    SELECT count(*)
      INTO new_entry_points
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'service_credential_application_find_active',
           'external_subject_identity_find_active'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF new_entry_points <> 2 THEN
        RAISE EXCEPTION
            'v011 assertion failed: the two authentication binding reads must be granted';
    END IF;

    SELECT count(*)
      INTO public_can_execute
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf' AND has_function_privilege('public', p.oid, 'EXECUTE');
    IF public_can_execute <> 0 THEN
        RAISE EXCEPTION 'v011 assertion failed: PUBLIC must not EXECUTE MTMF functions';
    END IF;

    SELECT count(*)
      INTO runtime_table_privileges
      FROM information_schema.table_privileges
     WHERE table_schema = 'mtmf'
       AND grantee = 'mtmf_runtime'
       AND table_name IN ('service_credential_application', 'external_subject_identity');
    IF runtime_table_privileges <> 0 THEN
        RAISE EXCEPTION 'v011 assertion failed: mtmf_runtime must not hold table privileges';
    END IF;
END;
$$;
