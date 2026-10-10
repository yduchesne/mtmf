-- v007: post-migration assertions (defense in depth).

DO $$
DECLARE
    old_overloads integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'mtmf' AND table_name = 'tenant' AND column_name = 'lifecycle'
    ) THEN
        RAISE EXCEPTION 'v007 assertion failed: mtmf.tenant.lifecycle column is missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'mtmf' AND table_name = 'identity' AND column_name = 'origin'
    ) THEN
        RAISE EXCEPTION 'v007 assertion failed: mtmf.identity.origin column is missing';
    END IF;

    SELECT count(*)
      INTO old_overloads
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN ('tenant_add', 'tenant_save', 'identity_add')
       AND pg_get_function_identity_arguments(p.oid) IN (
           'id_value uuid, name_value text, scope_value smallint, '
           'owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb',
           'id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb',
           'id_value uuid, principal_id_value uuid, name_value text, '
           'deletion_status_value smallint, extension_value jsonb'
       );
    IF old_overloads <> 0 THEN
        RAISE EXCEPTION
            'v007 assertion failed: stale pre-origin/lifecycle function overloads remain';
    END IF;

    IF NOT has_function_privilege(
        'mtmf_runtime',
        'mtmf.tenant_add(uuid, text, smallint, uuid, smallint, smallint, jsonb)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'v007 assertion failed: runtime cannot EXECUTE the new tenant_add signature';
    END IF;

    IF NOT has_function_privilege(
        'mtmf_runtime',
        'mtmf.identity_add(uuid, uuid, text, smallint, smallint, jsonb)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'v007 assertion failed: runtime cannot EXECUTE the new identity_add signature';
    END IF;
END;
$$;
