-- v014: post-migration assertions (defense in depth).
--
-- These checks run inside the migration transaction and fail it if the
-- approved PR 22 isolated-foundation posture was not achieved. The mandatory
-- post-upgrade runtime verifier (exact signature manifest) remains
-- authoritative; v014 adds NO runtime-granted function, so the manifest is
-- unchanged at 78.

DO $$
DECLARE
    missing_tables integer;
    runtime_executable integer;
    public_can_execute integer;
    runtime_table_privilege integer;
    active_index integer;
BEGIN
    SELECT count(*)
      INTO missing_tables
      FROM (VALUES
          ('application_onboarding_entitlement'),
          ('application_onboarding_entitlement_event')
      ) AS t(name)
     WHERE NOT EXISTS (
         SELECT 1 FROM information_schema.tables
          WHERE table_schema = 'mtmf' AND table_name = t.name
     );
    IF missing_tables <> 0 THEN
        RAISE EXCEPTION 'v014 assertion failed: onboarding-entitlement tables are missing';
    END IF;

    -- No v014 function is runtime-executable.
    SELECT count(*)
      INTO runtime_executable
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'guard_application_onboarding_entitlement',
           'guard_application_onboarding_entitlement_event',
           'application_onboarding_entitlement_grant',
           'application_onboarding_entitlement_revoke',
           'application_onboarding_entitlement_get',
           'application_onboarding_entitlement_find_by_application',
           'application_onboarding_entitlement_event_find_by_entitlement'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF runtime_executable <> 0 THEN
        RAISE EXCEPTION
            'v014 assertion failed: mtmf_runtime must not EXECUTE any onboarding-'
            'entitlement function (found %)', runtime_executable;
    END IF;

    -- PUBLIC holds no EXECUTE on any v014 function.
    SELECT count(*)
      INTO public_can_execute
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL aclexplode(
          coalesce(p.proacl, acldefault('f', p.proowner))
      ) AS a
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'guard_application_onboarding_entitlement',
           'guard_application_onboarding_entitlement_event',
           'application_onboarding_entitlement_grant',
           'application_onboarding_entitlement_revoke',
           'application_onboarding_entitlement_get',
           'application_onboarding_entitlement_find_by_application',
           'application_onboarding_entitlement_event_find_by_entitlement'
       )
       AND a.grantee = 0
       AND a.privilege_type = 'EXECUTE';
    IF public_can_execute <> 0 THEN
        RAISE EXCEPTION
            'v014 assertion failed: PUBLIC must not EXECUTE onboarding-entitlement functions';
    END IF;

    -- The runtime holds no table privilege on the new tables.
    SELECT count(*)
      INTO runtime_table_privilege
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'mtmf'
       AND c.relname IN (
           'application_onboarding_entitlement',
           'application_onboarding_entitlement_event'
       )
       AND (
           has_table_privilege('mtmf_runtime', c.oid, 'SELECT')
           OR has_table_privilege('mtmf_runtime', c.oid, 'INSERT')
           OR has_table_privilege('mtmf_runtime', c.oid, 'UPDATE')
           OR has_table_privilege('mtmf_runtime', c.oid, 'DELETE')
           OR has_table_privilege('mtmf_runtime', c.oid, 'TRUNCATE')
       );
    IF runtime_table_privilege <> 0 THEN
        RAISE EXCEPTION
            'v014 assertion failed: mtmf_runtime retains % onboarding-entitlement '
            'table privilege(s)', runtime_table_privilege;
    END IF;

    -- The single-ACTIVE-per-Application partial unique index exists.
    SELECT count(*)
      INTO active_index
      FROM pg_catalog.pg_indexes
     WHERE schemaname = 'mtmf'
       AND indexname = 'application_onboarding_entitlement_active_unique';
    IF active_index <> 1 THEN
        RAISE EXCEPTION
            'v014 assertion failed: the single-ACTIVE entitlement unique index is missing';
    END IF;
END;
$$;
