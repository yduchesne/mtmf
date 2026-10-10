-- v009: post-migration assertions (defense in depth).
--
-- These checks run inside the migration transaction and fail it if the
-- approved PR 11 posture was not achieved. The mandatory post-upgrade
-- runtime verifier (exact signature manifest) remains authoritative.

DO $$
DECLARE
    missing_tables integer;
    management_roles integer;
    management_permissions integer;
    privileged_executable integer;
    public_can_execute integer;
BEGIN
    SELECT count(*)
      INTO missing_tables
      FROM (VALUES
          ('tenant_management_group'),
          ('tenant_management_group_membership'),
          ('tenant_management_group_actor_eligibility')
      ) AS t(name)
     WHERE NOT EXISTS (
         SELECT 1 FROM information_schema.tables
          WHERE table_schema = 'mtmf' AND table_name = t.name
     );
    IF missing_tables <> 0 THEN
        RAISE EXCEPTION 'v009 assertion failed: TenantManagementGroup tables are missing';
    END IF;

    SELECT count(*)
      INTO management_roles
      FROM mtmf.builtin_role
     WHERE role_urn IN (
         'urn:mtmf:iam:roles:system:root-tenant-management',
         'urn:mtmf:iam:roles:system:tenant-management'
     );
    IF management_roles <> 2 THEN
        RAISE EXCEPTION
            'v009 assertion failed: exactly 2 management Roles must be registered, found %',
            management_roles;
    END IF;

    SELECT count(*)
      INTO management_permissions
      FROM mtmf.permission AS p
      JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
     WHERE ps.role_urn IN (
         'urn:mtmf:iam:roles:system:root-tenant-management',
         'urn:mtmf:iam:roles:system:tenant-management'
     )
       AND ps.effect = 'allow'
       AND p.urn = 'urn:mtmf:iam:permissions:system:tenant:get-object';
    IF management_permissions <> 2 THEN
        RAISE EXCEPTION
            'v009 assertion failed: each management Role must own the approved Permission, found %',
            management_permissions;
    END IF;

    -- The ROOT singleton must be enforced by the database.
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_indexes
         WHERE schemaname = 'mtmf'
           AND indexname = 'tenant_management_group_root_singleton'
    ) THEN
        RAISE EXCEPTION
            'v009 assertion failed: ROOT TenantManagementGroup singleton index is missing';
    END IF;

    SELECT count(*)
      INTO privileged_executable
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'initialize_root_tenant_management_group',
           'create_tenant_management_group',
           'add_tenant_management_group_membership',
           'remove_tenant_management_group_membership',
           'add_tenant_management_group_actor_eligibility',
           'remove_tenant_management_group_actor_eligibility',
           'install_management_roles',
           'guard_tenant_management_group',
           'guard_tenant_management_group_membership',
           'guard_tenant_management_group_actor_eligibility',
           'create_root_management_group'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF privileged_executable <> 0 THEN
        RAISE EXCEPTION
            'v009 assertion failed: mtmf_runtime must not EXECUTE privileged TenantManagementGroup functions (found %)',
            privileged_executable;
    END IF;

    SELECT count(*)
      INTO public_can_execute
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL aclexplode(
          coalesce(p.proacl, acldefault('f', p.proowner))
      ) AS a
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'tenant_management_group_get',
           'tenant_management_group_find_by_manager',
           'tenant_management_group_membership_get',
           'tenant_management_group_membership_find_by_group',
           'tenant_management_group_membership_find_by_tenant',
           'tenant_management_group_actor_eligibility_get',
           'tenant_management_group_actor_eligibility_find_by_group',
           'tenant_management_group_actor_eligibility_find_by_identity',
           'root_registry_get'
       )
       AND a.grantee = 0
       AND a.privilege_type = 'EXECUTE';
    IF public_can_execute <> 0 THEN
        RAISE EXCEPTION
            'v009 assertion failed: PUBLIC must not EXECUTE the TenantManagementGroup runtime reads';
    END IF;
END;
$$;
