-- v013: convert the PR 19C security-mutation audit table to PostgreSQL 18
-- native monthly RANGE partitioning on ``occurred_at`` (UTC half-open months).
--
-- The conversion is a single all-or-nothing Alembic transaction. It renames
-- the v012 table aside, builds the partitioned parent, moves every historical
-- row without rewriting provenance, proves complete bidirectional equality,
-- and only then removes the renamed backup. Nothing is committed until the
-- whole file (and the following grant/assertion files) succeed.
--
-- The primary key becomes ``(occurred_at, id)`` because PostgreSQL cannot
-- enforce a partitioned UNIQUE/PK on ``occurred_at`` alone. ``id`` remains the
-- per-attempt operation UUID, not a database-global uniqueness key.

DO $$
DECLARE
    v_lock_table constant text := 'mtmf.security_mutation_audit';
    v_backup_table constant text := 'mtmf.security_mutation_audit_v012_backup';
    v_old_count bigint;
    v_hist_min timestamptz;
    v_hist_max timestamptz;
    v_null_occurred bigint;
    v_duplicate_keys bigint;
    v_hist_min_month date;
    v_hist_max_month date;
    v_span_months integer;
    v_current_month date;
    v_horizon date;
    v_first date;
    v_last date;
    v_month date;
    v_next date;
    v_lower timestamptz;
    v_upper timestamptz;
    v_child text;
    v_new_count bigint;
    v_difference bigint;
    v_misrouted bigint;
    v_parent_rows bigint;
BEGIN
    -- Deterministic timestamptz literal rendering for partition bounds and
    -- for the UTC month routing checks below.
    PERFORM set_config('TimeZone', 'UTC', true);

    -- Serialize the swap against any in-flight writer for the whole
    -- transaction: no audit row can be inserted between snapshot and copy.
    EXECUTE format('LOCK TABLE %s IN ACCESS EXCLUSIVE MODE', v_lock_table);

    SELECT count(*),
           min(occurred_at),
           max(occurred_at),
           count(*) FILTER (WHERE occurred_at IS NULL)
      INTO v_old_count, v_hist_min, v_hist_max, v_null_occurred
      FROM mtmf.security_mutation_audit;

    IF v_null_occurred > 0 THEN
        RAISE EXCEPTION
            'v013 migration refused: security_mutation_audit contains % rows with NULL occurred_at',
            v_null_occurred;
    END IF;

    SELECT count(*)
      INTO v_duplicate_keys
      FROM (
          SELECT 1
            FROM mtmf.security_mutation_audit
           GROUP BY occurred_at, id
          HAVING count(*) > 1
      ) AS duplicates;
    IF v_duplicate_keys > 0 THEN
        RAISE EXCEPTION
            'v013 migration refused: security_mutation_audit contains % duplicate (occurred_at, id) groups',
            v_duplicate_keys;
    END IF;

    IF v_hist_min IS NOT NULL THEN
        v_hist_min_month := date_trunc('month', v_hist_min AT TIME ZONE 'UTC')::date;
        v_hist_max_month := date_trunc('month', v_hist_max AT TIME ZONE 'UTC')::date;
        v_span_months :=
            (extract(year FROM v_hist_max_month)::int
             - extract(year FROM v_hist_min_month)::int) * 12
            + (extract(month FROM v_hist_max_month)::int
               - extract(month FROM v_hist_min_month)::int) + 1;
        IF v_span_months > 120 THEN
            RAISE EXCEPTION
                'v013 migration refused: security_mutation_audit spans % historical months '
                '(the approved initial-partition bound is 120); operator decision required',
                v_span_months;
        END IF;
    END IF;

    -- 1. Rename the v012 table aside so its object names are freed.
    ALTER TABLE mtmf.security_mutation_audit RENAME TO security_mutation_audit_v012_backup;
    ALTER TABLE mtmf.security_mutation_audit_v012_backup
        DROP CONSTRAINT security_mutation_audit_pk;
    DROP INDEX mtmf.security_mutation_audit_tenant_occurred_idx;
    DROP INDEX mtmf.security_mutation_audit_target_occurred_idx;
    DROP TRIGGER security_mutation_audit_update_guard
        ON mtmf.security_mutation_audit_v012_backup;
    DROP TRIGGER security_mutation_audit_delete_guard
        ON mtmf.security_mutation_audit_v012_backup;
    DROP TRIGGER security_mutation_audit_truncate_guard
        ON mtmf.security_mutation_audit_v012_backup;

    -- 2. Build the partitioned parent with the exact v012 column/check
    --    definitions, but a composite primary key.
    CREATE TABLE mtmf.security_mutation_audit (
        id uuid NOT NULL,
        occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        authorized_at timestamptz NOT NULL,
        actor_identity_id uuid NOT NULL,
        actor_principal_id uuid NOT NULL,
        tenant_id uuid NOT NULL,
        application_id uuid NOT NULL,
        action_urn text NOT NULL,
        target_kind text NOT NULL,
        target_id uuid NOT NULL,
        subject_identity_id uuid NOT NULL,
        outcome text NOT NULL,
        CONSTRAINT security_mutation_audit_pk PRIMARY KEY (occurred_at, id),
        CONSTRAINT security_mutation_audit_outcome_check CHECK (outcome = 'CREATED'),
        CONSTRAINT security_mutation_audit_target_kind_check
            CHECK (target_kind = 'identity_group_membership'),
        CONSTRAINT security_mutation_audit_action_urn_check
            CHECK (action_urn =
                'urn:mtmf:iam:actions:system:identity-group-membership:add-object')
    ) PARTITION BY RANGE (occurred_at);

    CREATE INDEX security_mutation_audit_tenant_occurred_idx
        ON mtmf.security_mutation_audit (tenant_id, occurred_at DESC);
    CREATE INDEX security_mutation_audit_target_occurred_idx
        ON mtmf.security_mutation_audit (target_kind, target_id, occurred_at DESC);

    CREATE TRIGGER security_mutation_audit_update_guard
        BEFORE UPDATE ON mtmf.security_mutation_audit
        FOR EACH ROW EXECUTE FUNCTION mtmf.guard_security_mutation_audit();
    CREATE TRIGGER security_mutation_audit_delete_guard
        BEFORE DELETE ON mtmf.security_mutation_audit
        FOR EACH ROW EXECUTE FUNCTION mtmf.guard_security_mutation_audit();
    CREATE TRIGGER security_mutation_audit_truncate_guard
        BEFORE TRUNCATE ON mtmf.security_mutation_audit
        FOR EACH STATEMENT EXECUTE FUNCTION mtmf.guard_security_mutation_audit();

    -- 3. Attach every historical month, the current UTC month, and the next
    --    twelve months. Missing months inside the span are filled so that any
    --    timestamp in the interval routes to a real partition.
    v_current_month := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
    v_horizon := (v_current_month + interval '12 months')::date;
    IF v_hist_min IS NULL THEN
        v_first := v_current_month;
        v_last := v_horizon;
    ELSE
        v_first := least(
            date_trunc('month', v_hist_min AT TIME ZONE 'UTC')::date,
            v_current_month
        );
        v_last := greatest(
            date_trunc('month', v_hist_max AT TIME ZONE 'UTC')::date,
            v_horizon
        );
    END IF;

    v_month := v_first;
    WHILE v_month <= v_last LOOP
        v_next := (v_month + interval '1 month')::date;
        v_lower := make_timestamptz(
            extract(year FROM v_month)::int, extract(month FROM v_month)::int,
            1, 0, 0, 0, 'UTC'
        );
        v_upper := make_timestamptz(
            extract(year FROM v_next)::int, extract(month FROM v_next)::int,
            1, 0, 0, 0, 'UTC'
        );
        v_child := 'security_mutation_audit_y'
            || to_char(v_month, 'YYYY') || 'm' || to_char(v_month, 'MM');
        EXECUTE format(
            'CREATE TABLE mtmf.%I PARTITION OF mtmf.security_mutation_audit '
            'FOR VALUES FROM (%L) TO (%L)',
            v_child, v_lower, v_upper
        );
        -- Statement-level TRUNCATE triggers are not cloned to partitions, so
        -- each direct child needs its own append-only guard.
        EXECUTE format(
            'CREATE TRIGGER security_mutation_audit_truncate_guard '
            'BEFORE TRUNCATE ON mtmf.%I FOR EACH STATEMENT '
            'EXECUTE FUNCTION mtmf.guard_security_mutation_audit()',
            v_child
        );
        EXECUTE format('ALTER TABLE mtmf.%I OWNER TO mtmf_owner', v_child);
        EXECUTE format('REVOKE ALL ON TABLE mtmf.%I FROM PUBLIC', v_child);
        EXECUTE format('REVOKE ALL ON TABLE mtmf.%I FROM mtmf_runtime', v_child);
        v_month := v_next;
    END LOOP;

    -- 4. Copy every historical row with an explicit column list. No
    --    ``INSERT ... SELECT *`` and no ON CONFLICT: the evidence is moved
    --    verbatim or the transaction aborts.
    INSERT INTO mtmf.security_mutation_audit (
        id,
        occurred_at,
        authorized_at,
        actor_identity_id,
        actor_principal_id,
        tenant_id,
        application_id,
        action_urn,
        target_kind,
        target_id,
        subject_identity_id,
        outcome
    )
    SELECT
        id,
        occurred_at,
        authorized_at,
        actor_identity_id,
        actor_principal_id,
        tenant_id,
        application_id,
        action_urn,
        target_kind,
        target_id,
        subject_identity_id,
        outcome
      FROM mtmf.security_mutation_audit_v012_backup;

    SELECT count(*) INTO v_new_count FROM mtmf.security_mutation_audit;
    IF v_new_count <> v_old_count THEN
        RAISE EXCEPTION
            'v013 migration refused: copied row count % differs from source %',
            v_new_count, v_old_count;
    END IF;

    SELECT count(*) INTO v_difference
      FROM (
          SELECT id, occurred_at, authorized_at, actor_identity_id, actor_principal_id,
                 tenant_id, application_id, action_urn, target_kind, target_id,
                 subject_identity_id, outcome
            FROM mtmf.security_mutation_audit_v012_backup
          EXCEPT ALL
          SELECT id, occurred_at, authorized_at, actor_identity_id, actor_principal_id,
                 tenant_id, application_id, action_urn, target_kind, target_id,
                 subject_identity_id, outcome
            FROM mtmf.security_mutation_audit
      ) AS missing_rows;
    IF v_difference <> 0 THEN
        RAISE EXCEPTION
            'v013 migration refused: % source audit rows are absent from the partitioned table',
            v_difference;
    END IF;

    SELECT count(*) INTO v_difference
      FROM (
          SELECT id, occurred_at, authorized_at, actor_identity_id, actor_principal_id,
                 tenant_id, application_id, action_urn, target_kind, target_id,
                 subject_identity_id, outcome
            FROM mtmf.security_mutation_audit
          EXCEPT ALL
          SELECT id, occurred_at, authorized_at, actor_identity_id, actor_principal_id,
                 tenant_id, application_id, action_urn, target_kind, target_id,
                 subject_identity_id, outcome
            FROM mtmf.security_mutation_audit_v012_backup
      ) AS extra_rows;
    IF v_difference <> 0 THEN
        RAISE EXCEPTION
            'v013 migration refused: % partitioned audit rows have no source',
            v_difference;
    END IF;

    -- No row may sit in the parent itself (that would mean an unpartitioned
    -- or DEFAULT placement) and every row must route to its UTC month child.
    SELECT count(*) INTO v_parent_rows
      FROM mtmf.security_mutation_audit
     WHERE tableoid = 'mtmf.security_mutation_audit'::regclass;
    IF v_parent_rows <> 0 THEN
        RAISE EXCEPTION
            'v013 migration refused: % audit rows are not stored in a partition',
            v_parent_rows;
    END IF;

    SELECT count(*) INTO v_misrouted
      FROM mtmf.security_mutation_audit AS a
      JOIN pg_catalog.pg_class AS c ON c.oid = a.tableoid
     WHERE c.relname <> 'security_mutation_audit_y'
           || to_char(a.occurred_at AT TIME ZONE 'UTC', 'YYYY') || 'm'
           || to_char(a.occurred_at AT TIME ZONE 'UTC', 'MM');
    IF v_misrouted <> 0 THEN
        RAISE EXCEPTION
            'v013 migration refused: % audit rows are routed to a wrong monthly partition',
            v_misrouted;
    END IF;

    -- 5. Only now remove the renamed source. No CASCADE: a dependency here is
    --    a STOP, not something to force through.
    EXECUTE format('DROP TABLE %s', v_backup_table);

    EXECUTE format('ALTER TABLE %s OWNER TO mtmf_owner', v_lock_table);
    EXECUTE format('REVOKE ALL ON TABLE %s FROM PUBLIC', v_lock_table);
    EXECUTE format('REVOKE ALL ON TABLE %s FROM mtmf_runtime', v_lock_table);
END;
$$;
