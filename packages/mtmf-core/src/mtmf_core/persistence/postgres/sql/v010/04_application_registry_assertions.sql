-- v010: post-migration assertions (defense in depth).
--
-- These checks run inside the migration transaction and fail it if the
-- approved PR 13 posture was not achieved. The mandatory post-upgrade
-- runtime verifier (exact signature manifest) remains authoritative.

DO $$
DECLARE
    missing_tables integer;
    privileged_executable integer;
    public_can_execute integer;
    approved_count integer;
    new_entry_points integer;
BEGIN
    SELECT count(*)
      INTO missing_tables
      FROM (VALUES
          ('application'),
          ('application_tenant_registration'),
          ('tenant_application_subscription')
      ) AS t(name)
     WHERE NOT EXISTS (
         SELECT 1 FROM information_schema.tables
          WHERE table_schema = 'mtmf' AND table_name = t.name
     );
    IF missing_tables <> 0 THEN
        RAISE EXCEPTION 'v010 assertion failed: Application-registry tables are missing';
    END IF;

    -- Exactly 75 approved runtime entry points: 67 through revision 0009
    -- plus the 8 Application-registry reads granted in 03.
    SELECT count(*)
      INTO approved_count
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF approved_count <> 75 THEN
        RAISE EXCEPTION
            'v010 assertion failed: runtime EXECUTE allowlist must be exactly 75 '
            'functions (67 through v009 plus 8 Application-registry reads), found %',
            approved_count;
    END IF;

    SELECT count(*)
      INTO new_entry_points
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'application_get',
           'application_get_by_key',
           'application_tenant_registration_get',
           'application_tenant_registration_find_by_application_and_tenant',
           'application_tenant_registration_find_by_tenant',
           'tenant_application_subscription_get',
           'tenant_application_subscription_find_by_application_and_tenant',
           'tenant_application_subscription_find_by_tenant'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF new_entry_points <> 8 THEN
        RAISE EXCEPTION
            'v010 assertion failed: expected 8 runtime-granted Application-registry '
            'reads, found %', new_entry_points;
    END IF;

    -- Privileged mutation and guard functions are NOT runtime-executable.
    SELECT count(*)
      INTO privileged_executable
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'application_add',
           'application_save',
           'application_tenant_registration_add',
           'application_tenant_registration_save',
           'tenant_application_subscription_add',
           'tenant_application_subscription_save',
           'guard_application_registry_application',
           'guard_application_tenant_registration',
           'guard_tenant_application_subscription'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF privileged_executable <> 0 THEN
        RAISE EXCEPTION
            'v010 assertion failed: mtmf_runtime must not EXECUTE privileged '
            'Application-registry functions (found %)', privileged_executable;
    END IF;

    -- PUBLIC holds no EXECUTE on any v010 function.
    SELECT count(*)
      INTO public_can_execute
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL aclexplode(
          coalesce(p.proacl, acldefault('f', p.proowner))
      ) AS a
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'application_add',
           'application_save',
           'application_tenant_registration_add',
           'application_tenant_registration_save',
           'tenant_application_subscription_add',
           'tenant_application_subscription_save',
           'application_get',
           'application_get_by_key',
           'application_tenant_registration_get',
           'application_tenant_registration_find_by_application_and_tenant',
           'application_tenant_registration_find_by_tenant',
           'tenant_application_subscription_get',
           'tenant_application_subscription_find_by_application_and_tenant',
           'tenant_application_subscription_find_by_tenant',
           'guard_application_registry_application',
           'guard_application_tenant_registration',
           'guard_tenant_application_subscription'
       )
       AND a.grantee = 0
       AND a.privilege_type = 'EXECUTE';
    IF public_can_execute <> 0 THEN
        RAISE EXCEPTION
            'v010 assertion failed: PUBLIC must not EXECUTE Application-registry functions';
    END IF;

    -- The runtime still holds no table/sequence privilege.
    SELECT count(*)
      INTO privileged_executable
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'mtmf'
       AND c.relname IN (
           'application',
           'application_tenant_registration',
           'tenant_application_subscription'
       )
       AND (
           has_table_privilege('mtmf_runtime', c.oid, 'SELECT')
           OR has_table_privilege('mtmf_runtime', c.oid, 'INSERT')
           OR has_table_privilege('mtmf_runtime', c.oid, 'UPDATE')
           OR has_table_privilege('mtmf_runtime', c.oid, 'DELETE')
           OR has_table_privilege('mtmf_runtime', c.oid, 'TRUNCATE')
       );
    IF privileged_executable <> 0 THEN
        RAISE EXCEPTION
            'v010 assertion failed: mtmf_runtime retains % Application-registry '
            'table privilege(s)', privileged_executable;
    END IF;
END;
$$;
