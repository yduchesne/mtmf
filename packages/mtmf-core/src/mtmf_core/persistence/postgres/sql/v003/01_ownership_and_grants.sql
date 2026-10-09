-- v003: MTMF ownership normalization and default-deny grants.
--
-- This file executes as the MTMF owner role (the migration connection runs
-- under SET ROLE mtmf_owner). It:
--
--   1. fails loudly with an actionable message if any object in the
--      ``mtmf`` schema is still owned by a legacy login (the
--      administrator must run the one-time ownership handoff first);
--   2. re-asserts mtmf_owner ownership of the schema;
--   3. removes every PUBLIC grant and every runtime grant, so effective
--      rights are denied through PUBLIC, role membership, and schema
--      defaults alike;
--   4. grants the runtime role exactly what it needs to reach the
--      approved functions: USAGE on the schema (no CREATE).
--
-- PostgreSQL REVOKE is additive to existing grants and PUBLIC defaults can
-- still supply effective privileges, so this file revokes from PUBLIC
-- explicitly and the runtime grants are enumerated in 03.

-- 1. Ownership handoff must already have happened.
DO $$
DECLARE
    offenders text;
BEGIN
    SELECT string_agg(obj, ', ')
      INTO offenders
      FROM (
            SELECT format('%s (%s)', c.relname, pg_get_userbyid(c.relowner)) AS obj
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'mtmf'
               AND pg_get_userbyid(c.relowner) <> 'mtmf_owner'
            UNION ALL
            SELECT format('function %s (%s)', p.proname, pg_get_userbyid(p.proowner))
              FROM pg_catalog.pg_proc p
              JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'mtmf'
               AND pg_get_userbyid(p.proowner) <> 'mtmf_owner'
            UNION ALL
            SELECT format('schema %s (%s)', n.nspname, pg_get_userbyid(n.nspowner))
              FROM pg_catalog.pg_namespace n
             WHERE n.nspname = 'mtmf'
               AND pg_get_userbyid(n.nspowner) <> 'mtmf_owner'
           ) AS offenders;
    IF offenders IS NOT NULL THEN
        RAISE EXCEPTION
          'revision 0003 cannot proceed: these mtmf objects are not owned by '
          'mtmf_owner: %. Run the administrator ownership handoff '
          '(`scripts/mtmf-provision-roles.py --adopt-existing-schema`) first.',
          offenders;
    END IF;
END;
$$;

-- 2. Schema ownership.
ALTER SCHEMA mtmf OWNER TO mtmf_owner;

-- 3. Default-deny across the schema.
REVOKE CREATE ON SCHEMA mtmf FROM PUBLIC;
REVOKE ALL ON SCHEMA mtmf FROM mtmf_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA mtmf FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mtmf FROM mtmf_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mtmf FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mtmf FROM mtmf_runtime;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mtmf FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mtmf FROM mtmf_runtime;

-- 4. Explicit schema USAGE for the restricted and deployment logins.
GRANT USAGE ON SCHEMA mtmf TO mtmf_runtime;
GRANT USAGE ON SCHEMA mtmf TO mtmf_migrator;
