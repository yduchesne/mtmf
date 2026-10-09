-- v003: post-migration privilege assertions.
--
-- These checks run inside the migration transaction and fail the migration
-- (rolling back every grant/ownership change) if the intended effective
-- posture was not achieved. They assert effective privileges via
-- ``has_table_privilege``/``has_sequence_privilege``/``has_schema_privilege``
-- and the ACL for PUBLIC, not merely the absence of ACL text.

DO $$
DECLARE
    offenders text;
    granted integer;
BEGIN
    -- No runtime table privilege of any kind.
    SELECT string_agg(format('%s:%s', c.relname, p.privilege), ', ')
      INTO offenders
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN (
          VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                 ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')
      ) AS p(privilege)
     WHERE n.nspname = 'mtmf'
       AND c.relkind IN ('r', 'p', 'v', 'm')
       AND has_table_privilege('mtmf_runtime', c.oid, p.privilege);
    IF offenders IS NOT NULL THEN
        RAISE EXCEPTION 'PRIV-01 assertion failed: runtime retains table privilege: %', offenders;
    END IF;

    -- No runtime sequence privilege.
    SELECT string_agg(format('%s:%s', c.relname, p.privilege), ', ')
      INTO offenders
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) AS p(privilege)
     WHERE n.nspname = 'mtmf'
       AND c.relkind = 'S'
       AND has_sequence_privilege('mtmf_runtime', c.oid, p.privilege);
    IF offenders IS NOT NULL THEN
        RAISE EXCEPTION
            'PRIV-13 assertion failed: runtime retains sequence privilege: %', offenders;
    END IF;

    -- Runtime may not create or drop anything in the MTMF schema.
    IF has_schema_privilege('mtmf_runtime', 'mtmf', 'CREATE') THEN
        RAISE EXCEPTION 'PRIV-05 assertion failed: runtime retains CREATE on schema mtmf';
    END IF;

    -- Runtime EXECUTE is exactly the six approved removal signatures.
    SELECT count(*)
      INTO granted
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF granted <> 6 THEN
        RAISE EXCEPTION
            'PRIV-04 assertion failed: runtime EXECUTE allowlist must be exactly six '
            'functions, found %', granted;
    END IF;

    -- All six approved functions are owner-owned SECURITY DEFINER.
    SELECT count(*)
      INTO granted
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname LIKE 'remove\_%\_membership'
       AND p.prosecdef
       AND pg_get_userbyid(p.proowner) = 'mtmf_owner';
    IF granted <> 6 THEN
        RAISE EXCEPTION
            'PRIV-15 assertion failed: expected six owner-owned SECURITY DEFINER '
            'removal functions, found %', granted;
    END IF;

    -- PUBLIC holds no EXECUTE on any MTMF function.
    SELECT count(*)
      INTO granted
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND EXISTS (
           SELECT 1
             FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) AS a
            WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'
       );
    IF granted <> 0 THEN
        RAISE EXCEPTION
            'PRIV-09 assertion failed: PUBLIC retains EXECUTE on % mtmf functions', granted;
    END IF;
END;
$$;
