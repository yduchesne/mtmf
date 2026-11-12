-- v015: post-migration assertions (defense in depth).
--
-- These checks run inside the migration transaction and fail it unless the
-- approved PR 23 owner-only, non-runtime posture and the preserved PR 10
-- root/stewardship guards were achieved. The mandatory post-upgrade runtime
-- privilege verifier remains authoritative; v015 adds NO runtime-granted
-- function, so the reviewed runtime manifest remains 78 signatures.

DO $$
DECLARE
    bad_functions integer;
    runtime_executable integer;
    public_can_execute integer;
    runtime_table_privilege integer;
    missing_triggers integer;
    audit_operations text[];
    designation_pk text[];
BEGIN
    -- Both exact signatures exist, are owner-owned INVOKER functions with an
    -- empty pinned search_path.
    SELECT count(*)
      INTO bad_functions
      FROM (VALUES
          ('mtmf.onboarding_subject_prepare(text,text,uuid,uuid,uuid)'),
          ('mtmf.onboarding_initial_steward_attach(uuid,text,text,uuid,uuid)')
      ) AS expected(signature)
     WHERE NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc p
           JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'mtmf'
            AND p.oid::regprocedure::text = expected.signature
            AND pg_catalog.pg_get_userbyid(p.proowner) = 'mtmf_owner'
            AND p.prosecdef = false
            AND p.proconfig IS NOT DISTINCT FROM ARRAY['search_path=""']::text[]
     );
    IF bad_functions <> 0 THEN
        RAISE EXCEPTION
            'v015 assertion failed: an onboarding participant is missing or has the wrong owner/invoker/search_path posture';
    END IF;

    -- No v015 function is runtime-executable.
    SELECT count(*)
      INTO runtime_executable
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN ('onboarding_subject_prepare', 'onboarding_initial_steward_attach')
       AND pg_catalog.has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF runtime_executable <> 0 THEN
        RAISE EXCEPTION
            'v015 assertion failed: mtmf_runtime must not EXECUTE the onboarding participants (found %)',
            runtime_executable;
    END IF;

    -- PUBLIC holds no EXECUTE on either function.
    SELECT count(*)
      INTO public_can_execute
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
          coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))
      ) AS a
     WHERE n.nspname = 'mtmf'
       AND p.proname IN ('onboarding_subject_prepare', 'onboarding_initial_steward_attach')
       AND a.grantee = 0
       AND a.privilege_type = 'EXECUTE';
    IF public_can_execute <> 0 THEN
        RAISE EXCEPTION
            'v015 assertion failed: PUBLIC must not EXECUTE the onboarding participants';
    END IF;

    -- No table privilege was expanded to the restricted runtime.
    SELECT count(*)
      INTO runtime_table_privilege
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL unnest(
          ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']
      ) AS privilege(name)
     WHERE n.nspname = 'mtmf'
       AND c.relname IN (
           'principal',
           'identity',
           'external_subject_identity',
           'principal_tenant_membership',
           'identity_tenant_membership',
           'identity_role_assignment',
           'stewardship_designation',
           'stewardship_audit'
       )
       AND pg_catalog.has_table_privilege('mtmf_runtime', c.oid, privilege.name);
    IF runtime_table_privilege <> 0 THEN
        RAISE EXCEPTION
            'v015 assertion failed: mtmf_runtime retains % PR 23 table privilege(s)',
            runtime_table_privilege;
    END IF;

    -- The reviewed runtime EXECUTE manifest is unchanged at 78 signatures.
    SELECT count(*)
      INTO runtime_executable
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND pg_catalog.has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF runtime_executable <> 78 THEN
        RAISE EXCEPTION
            'v015 assertion failed: the runtime EXECUTE manifest must remain 78 (found %)',
            runtime_executable;
    END IF;

    -- The original root/stewardship protection triggers are still installed.
    SELECT count(*)
      INTO missing_triggers
      FROM (VALUES
          ('root_registry_guard'),
          ('root_registry_delete_guard'),
          ('root_tenant_guard'),
          ('root_principal_guard'),
          ('root_identity_guard'),
          ('stewardship_designation_guard'),
          ('steward_principal_guard'),
          ('steward_identity_guard'),
          ('principal_tenant_membership_root_steward_guard'),
          ('identity_tenant_membership_root_steward_guard'),
          ('tenant_activation_guard'),
          ('stewardship_audit_update_guard'),
          ('stewardship_audit_delete_guard'),
          ('identity_role_assignment_steward_guard'),
          ('group_role_assignment_steward_guard'),
          ('identity_group_membership_steward_guard'),
          ('steward_group_guard')
      ) AS expected(name)
     WHERE NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_trigger t
           JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'mtmf'
            AND t.tgname = expected.name
            AND t.tgisinternal = false
     );
    IF missing_triggers <> 0 THEN
        RAISE EXCEPTION
            'v015 assertion failed: % original root/stewardship trigger(s) are missing',
            missing_triggers;
    END IF;

    -- The audit CHECK accepts exactly the four historical values plus
    -- INITIAL_ONBOARDING.
    SELECT pg_catalog.array_agg(m[1] ORDER BY m[1])
      INTO audit_operations
      FROM pg_catalog.pg_constraint c
      CROSS JOIN LATERAL pg_catalog.regexp_matches(
          pg_catalog.pg_get_constraintdef(c.oid), '''([A-Z_]+)''', 'g'
      ) AS m
     WHERE c.conrelid = 'mtmf.stewardship_audit'::regclass
       AND c.conname = 'stewardship_audit_operation_check';
    IF audit_operations IS DISTINCT FROM ARRAY[
        'BOOTSTRAP', 'INITIAL_ONBOARDING', 'RECOVERY', 'ROOT_IDENTITY_RECOVERY', 'TRANSFER'
    ]::text[] THEN
        RAISE EXCEPTION
            'v015 assertion failed: the stewardship audit operation CHECK does not admit exactly the five approved values (found %)',
            audit_operations;
    END IF;

    -- The designation remains a single-row-per-Tenant primary key.
    SELECT pg_catalog.array_agg(a.attname ORDER BY a.attname)
      INTO designation_pk
      FROM pg_catalog.pg_index i
      JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
     WHERE n.nspname = 'mtmf'
       AND c.relname = 'stewardship_designation'
       AND i.indisprimary;
    IF designation_pk IS DISTINCT FROM ARRAY['tenant_id']::text[] THEN
        RAISE EXCEPTION
            'v015 assertion failed: stewardship_designation must remain keyed by tenant_id only';
    END IF;
END;
$$;
