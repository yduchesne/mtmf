-- v013: post-migration assertions (defense in depth).
--
-- Verifies the partitioned parent shape, partition coverage and no-DEFAULT
-- posture, append-only guard inheritance, ownership/privilege preservation,
-- the unchanged 78-function runtime allowlist, and the privileged-only
-- maintenance helper. Uses catalog metadata, not DDL string matching.

DO $$
DECLARE
    v_parent constant regclass := 'mtmf.security_mutation_audit'::regclass;
    v_parent_oid oid := v_parent;
    v_relkind "char";
    v_partkey text;
    v_pk_attnums smallint[];
    v_column_mismatches integer;
    v_check_count integer;
    v_bad_check integer;
    v_default_partitions integer;
    v_backup regclass;
    v_current date;
    v_month date;
    v_child text;
    v_expected_bound text;
    v_present integer;
    v_parent_bad_triggers integer;
    v_child_bad_triggers integer;
    v_bad_owner integer;
    v_runtime_table_privileges integer;
    v_public_table_privileges integer;
    v_runtime_grant_count integer;
    v_maintenance_runtime boolean;
    v_maintenance_public integer;
    v_legacy_runtime boolean;
BEGIN
    PERFORM set_config('TimeZone', 'UTC', true);

    -- 1. Native declarative RANGE partitioning on occurred_at.
    SELECT c.relkind INTO v_relkind FROM pg_catalog.pg_class AS c WHERE c.oid = v_parent_oid;
    IF v_relkind <> 'p' THEN
        RAISE EXCEPTION 'v013 assertion failed: security_mutation_audit is not a partitioned table';
    END IF;
    v_partkey := pg_get_partkeydef(v_parent_oid);
    IF v_partkey <> 'RANGE (occurred_at)' THEN
        RAISE EXCEPTION 'v013 assertion failed: unexpected partition key %', v_partkey;
    END IF;

    -- 2. Composite primary key (occurred_at, id) in that order.
    SELECT con.conkey
      INTO v_pk_attnums
      FROM pg_catalog.pg_constraint AS con
     WHERE con.conrelid = v_parent_oid
       AND con.contype = 'p';
    IF v_pk_attnums IS DISTINCT FROM ARRAY[2, 1]::smallint[] THEN
        RAISE EXCEPTION 'v013 assertion failed: primary key is not (occurred_at, id)';
    END IF;

    -- 3. Exact columns, types, nullability and defaults.
    SELECT count(*)
      INTO v_column_mismatches
      FROM (
          VALUES
            (1, 'id', 'uuid', true, false),
            (2, 'occurred_at', 'timestamp with time zone', true, true),
            (3, 'authorized_at', 'timestamp with time zone', true, false),
            (4, 'actor_identity_id', 'uuid', true, false),
            (5, 'actor_principal_id', 'uuid', true, false),
            (6, 'tenant_id', 'uuid', true, false),
            (7, 'application_id', 'uuid', true, false),
            (8, 'action_urn', 'text', true, false),
            (9, 'target_kind', 'text', true, false),
            (10, 'target_id', 'uuid', true, false),
            (11, 'subject_identity_id', 'uuid', true, false),
            (12, 'outcome', 'text', true, false)
      ) AS expected(attnum, name, type, not_null, has_default)
      LEFT JOIN (
          SELECT a.attnum,
                 a.attname AS name,
                 format_type(a.atttypid, a.atttypmod) AS type,
                 a.attnotnull AS not_null,
                 (d.adbin IS NOT NULL
                  AND pg_get_expr(d.adbin, d.adrelid) LIKE '%clock_timestamp%') AS has_default
            FROM pg_catalog.pg_attribute AS a
            LEFT JOIN pg_catalog.pg_attrdef AS d
              ON d.adrelid = a.attrelid AND d.adnum = a.attnum
           WHERE a.attrelid = v_parent_oid
             AND a.attnum > 0
             AND NOT a.attisdropped
      ) AS actual USING (attnum, name, type, not_null, has_default)
     WHERE actual.attnum IS NULL;
    IF v_column_mismatches <> 0 THEN
        RAISE EXCEPTION 'v013 assertion failed: % columns differ from the v012 definition',
            v_column_mismatches;
    END IF;
    SELECT count(*)
      INTO v_column_mismatches
      FROM (
          SELECT a.attnum
            FROM pg_catalog.pg_attribute AS a
           WHERE a.attrelid = v_parent_oid
             AND a.attnum > 0
             AND NOT a.attisdropped
      ) AS cols
     WHERE cols.attnum > 12;
    IF v_column_mismatches <> 0 THEN
        RAISE EXCEPTION 'v013 assertion failed: security_mutation_audit has unexpected extra columns';
    END IF;

    -- 4. Exactly the three v012 CHECK constraints.
    SELECT count(*) INTO v_check_count
      FROM pg_catalog.pg_constraint AS con
     WHERE con.conrelid = v_parent_oid AND con.contype = 'c';
    IF v_check_count <> 3 THEN
        RAISE EXCEPTION 'v013 assertion failed: expected 3 CHECK constraints, found %', v_check_count;
    END IF;
    SELECT count(*) INTO v_bad_check
      FROM pg_catalog.pg_constraint AS con
     WHERE con.conrelid = v_parent_oid
       AND con.contype = 'c'
       AND con.conname NOT IN (
           'security_mutation_audit_outcome_check',
           'security_mutation_audit_target_kind_check',
           'security_mutation_audit_action_urn_check'
       );
    IF v_bad_check <> 0 THEN
        RAISE EXCEPTION 'v013 assertion failed: unexpected CHECK constraint on the audit table';
    END IF;

    -- 5. No DEFAULT partition.
    SELECT count(*) INTO v_default_partitions
      FROM pg_catalog.pg_inherits AS i
      JOIN pg_catalog.pg_class AS c ON c.oid = i.inhrelid
     WHERE i.inhparent = v_parent_oid
       AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT';
    IF v_default_partitions <> 0 THEN
        RAISE EXCEPTION 'v013 assertion failed: a DEFAULT partition was created';
    END IF;

    -- 6. The current UTC month and the next twelve are attached with the
    --    expected half-open UTC bounds.
    v_current := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
    FOR v_month IN
        SELECT (v_current + (offset_months || ' months')::interval)::date
          FROM generate_series(0, 12) AS offset_months
    LOOP
        v_child := 'security_mutation_audit_y'
            || to_char(v_month, 'YYYY') || 'm' || to_char(v_month, 'MM');
        v_expected_bound := format(
            'FOR VALUES FROM (%L) TO (%L)',
            make_timestamptz(
                extract(year FROM v_month)::int, extract(month FROM v_month)::int,
                1, 0, 0, 0, 'UTC'
            ),
            make_timestamptz(
                extract(year FROM (v_month + interval '1 month'))::int,
                extract(month FROM (v_month + interval '1 month'))::int,
                1, 0, 0, 0, 'UTC'
            )
        );
        SELECT count(*)
          INTO v_present
          FROM pg_catalog.pg_inherits AS i
          JOIN pg_catalog.pg_class AS c ON c.oid = i.inhrelid
         WHERE i.inhparent = v_parent_oid
           AND c.relname = v_child
           AND pg_get_expr(c.relpartbound, c.oid) = v_expected_bound;
        IF v_present <> 1 THEN
            RAISE EXCEPTION 'v013 assertion failed: partition % is missing or has wrong bounds', v_child;
        END IF;
    END LOOP;

    -- 7. No stale backup table.
    v_backup := to_regclass('mtmf.security_mutation_audit_v012_backup');
    IF v_backup IS NOT NULL THEN
        RAISE EXCEPTION 'v013 assertion failed: the v012 backup table was not removed';
    END IF;

    -- 8. Append-only guards on the parent and every direct child.
    SELECT count(*) INTO v_parent_bad_triggers
      FROM (VALUES
          ('security_mutation_audit_update_guard'),
          ('security_mutation_audit_delete_guard'),
          ('security_mutation_audit_truncate_guard')
      ) AS names(tgname)
     WHERE NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_trigger AS t
          WHERE t.tgrelid = v_parent_oid
            AND t.tgname = names.tgname
            AND NOT t.tgisinternal
            AND t.tgenabled = 'O'
            AND t.tgfoid = 'mtmf.guard_security_mutation_audit()'::regprocedure
     );
    IF v_parent_bad_triggers <> 0 THEN
        RAISE EXCEPTION 'v013 assertion failed: a parent append-only trigger is missing or disabled';
    END IF;

    SELECT count(*) INTO v_child_bad_triggers
      FROM pg_catalog.pg_inherits AS i
      JOIN pg_catalog.pg_class AS c ON c.oid = i.inhrelid
     WHERE i.inhparent = v_parent_oid
       AND (
           SELECT count(*)
             FROM pg_catalog.pg_trigger AS t
            WHERE t.tgrelid = c.oid
              AND NOT t.tgisinternal
              AND t.tgenabled = 'O'
              AND t.tgfoid = 'mtmf.guard_security_mutation_audit()'::regprocedure
       ) <> 3;
    IF v_child_bad_triggers <> 0 THEN
        RAISE EXCEPTION
            'v013 assertion failed: % audit partitions lack the three append-only guards',
            v_child_bad_triggers;
    END IF;

    -- 9. Ownership and the absence of runtime/PUBLIC table privileges.
    SELECT count(*) INTO v_bad_owner
      FROM pg_catalog.pg_class AS c
      JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
     WHERE n.nspname = 'mtmf'
       AND (c.oid = v_parent_oid OR c.oid IN (
              SELECT i.inhrelid FROM pg_catalog.pg_inherits AS i WHERE i.inhparent = v_parent_oid
           ))
       AND pg_get_userbyid(c.relowner) <> 'mtmf_owner';
    IF v_bad_owner <> 0 THEN
        RAISE EXCEPTION 'v013 assertion failed: % audit relations are not owned by mtmf_owner', v_bad_owner;
    END IF;

    SELECT count(*) INTO v_runtime_table_privileges
      FROM pg_catalog.pg_class AS c
      JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
      CROSS JOIN unnest(ARRAY[
          'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'
      ]) AS p(privilege)
     WHERE n.nspname = 'mtmf'
       AND (c.oid = v_parent_oid OR c.oid IN (
              SELECT i.inhrelid FROM pg_catalog.pg_inherits AS i WHERE i.inhparent = v_parent_oid
           ))
       AND has_table_privilege('mtmf_runtime', c.oid, p.privilege);
    IF v_runtime_table_privileges <> 0 THEN
        RAISE EXCEPTION
            'v013 assertion failed: mtmf_runtime holds % audit table privileges',
            v_runtime_table_privileges;
    END IF;

    SELECT count(*) INTO v_public_table_privileges
      FROM pg_catalog.pg_class AS c
      JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
      CROSS JOIN unnest(ARRAY[
          'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'
      ]) AS p(privilege)
     WHERE n.nspname = 'mtmf'
       AND (c.oid = v_parent_oid OR c.oid IN (
              SELECT i.inhrelid FROM pg_catalog.pg_inherits AS i WHERE i.inhparent = v_parent_oid
           ))
       AND has_table_privilege('public', c.oid, p.privilege);
    IF v_public_table_privileges <> 0 THEN
        RAISE EXCEPTION 'v013 assertion failed: PUBLIC holds audit table privileges';
    END IF;

    -- 10. The runtime allowlist stays exactly 78 and the maintenance helper is
    --     privileged-only; the legacy unaudited add remains revoked.
    SELECT count(*)
      INTO v_runtime_grant_count
      FROM pg_catalog.pg_proc AS p
      JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF v_runtime_grant_count <> 78 THEN
        RAISE EXCEPTION
            'v013 assertion failed: runtime EXECUTE allowlist must be exactly 78 functions, found %',
            v_runtime_grant_count;
    END IF;

    SELECT has_function_privilege(
        'mtmf_runtime',
        'mtmf.ensure_security_mutation_audit_month(date)',
        'EXECUTE'
    ) INTO v_maintenance_runtime;
    IF v_maintenance_runtime THEN
        RAISE EXCEPTION 'v013 assertion failed: the maintenance helper is runtime-executable';
    END IF;
    SELECT count(*)
      INTO v_maintenance_public
      FROM pg_catalog.pg_proc AS p
     WHERE p.oid = 'mtmf.ensure_security_mutation_audit_month(date)'::regprocedure
       AND has_function_privilege('public', p.oid, 'EXECUTE');
    IF v_maintenance_public <> 0 THEN
        RAISE EXCEPTION 'v013 assertion failed: PUBLIC can EXECUTE the maintenance helper';
    END IF;

    SELECT has_function_privilege(
        'mtmf_runtime',
        'mtmf.identity_group_membership_add(uuid, uuid)',
        'EXECUTE'
    ) INTO v_legacy_runtime;
    IF v_legacy_runtime THEN
        RAISE EXCEPTION 'v013 assertion failed: the legacy membership-add function is runtime-executable';
    END IF;
END;
$$;
