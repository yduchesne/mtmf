-- v013: privileged, deterministic monthly-partition provisioning.
--
-- ``ensure_security_mutation_audit_month`` creates exactly one validated UTC
-- monthly partition of ``mtmf.security_mutation_audit`` if it is missing. It
-- is owner-owned and SECURITY INVOKER with a fixed empty ``search_path``: it
-- can only ever run as a login that already has DDL rights (an operator that
-- has explicitly assumed the MTMF owner role). It is never granted to
-- ``mtmf_runtime`` and provides no automatic retention, DETACH, or DROP path.

CREATE OR REPLACE FUNCTION mtmf.ensure_security_mutation_audit_month(p_month date)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    -- Fixed advisory-lock namespace ("MTMF" as a 32-bit integer). Combined
    -- with the calendar-month ordinal it serializes maintenance for one month
    -- without colliding with another application's advisory locks.
    c_lock_namespace constant integer := 1297362758;
    v_next date;
    v_lower timestamptz;
    v_upper timestamptz;
    v_child text;
    v_expected_bound text;
    v_parent_oid oid;
    v_child_oid oid;
    v_bound text;
    v_conflict record;
BEGIN
    IF p_month IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'ensure_security_mutation_audit_month requires a calendar month';
    END IF;
    IF p_month <> date_trunc('month', p_month)::date THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'ensure_security_mutation_audit_month requires the first day of a month';
    END IF;
    -- Bound so that both the month and its successor are representable dates.
    IF p_month < DATE '0001-01-01' OR p_month >= DATE '9999-12-01' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'ensure_security_mutation_audit_month month is out of the supported range';
    END IF;

    -- Bound rendering must be session-timezone independent so an existing
    -- partition is recognized identically everywhere.
    PERFORM set_config('TimeZone', 'UTC', true);

    v_next := (p_month + interval '1 month')::date;
    v_lower := make_timestamptz(
        extract(year FROM p_month)::int, extract(month FROM p_month)::int,
        1, 0, 0, 0, 'UTC'
    );
    v_upper := make_timestamptz(
        extract(year FROM v_next)::int, extract(month FROM v_next)::int,
        1, 0, 0, 0, 'UTC'
    );
    v_child := 'security_mutation_audit_y'
        || to_char(p_month, 'YYYY') || 'm' || to_char(p_month, 'MM');
    v_expected_bound := format('FOR VALUES FROM (%L) TO (%L)', v_lower, v_upper);
    v_parent_oid := 'mtmf.security_mutation_audit'::regclass;

    -- Serialize concurrent maintenance for this month before inspecting state.
    PERFORM pg_advisory_xact_lock(
        c_lock_namespace,
        (extract(year FROM p_month)::int * 12 + extract(month FROM p_month)::int)
    );

    SELECT c.oid
      INTO v_child_oid
      FROM pg_catalog.pg_class AS c
      JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
     WHERE n.nspname = 'mtmf'
       AND c.relname = v_child
       AND c.relkind = 'r';

    IF v_child_oid IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_inherits AS i
             WHERE i.inhrelid = v_child_oid
               AND i.inhparent = v_parent_oid
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = format(
                    'existing relation mtmf.%I is not a partition of security_mutation_audit',
                    v_child
                );
        END IF;
        SELECT pg_get_expr(c.relpartbound, c.oid)
          INTO v_bound
          FROM pg_catalog.pg_class AS c
         WHERE c.oid = v_child_oid;
        IF v_bound IS DISTINCT FROM v_expected_bound THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = format(
                    'existing partition mtmf.%I has unexpected bounds %s (expected %s)',
                    v_child, v_bound, v_expected_bound
                );
        END IF;
        RETURN;
    END IF;

    -- The name is free, but another partition may already cover the interval.
    -- Never create an overlapping partition and never a DEFAULT partition.
    SELECT c.relname, pg_get_expr(c.relpartbound, c.oid)
      INTO v_conflict
      FROM pg_catalog.pg_inherits AS i
      JOIN pg_catalog.pg_class AS c ON c.oid = i.inhrelid
     WHERE i.inhparent = v_parent_oid
       AND pg_get_expr(c.relpartbound, c.oid) = v_expected_bound
     LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = format(
                'the interval for %s is already covered by partition mtmf.%I',
                p_month, v_conflict.relname
            );
    END IF;

    EXECUTE format(
        'CREATE TABLE mtmf.%I PARTITION OF mtmf.security_mutation_audit '
        'FOR VALUES FROM (%L) TO (%L)',
        v_child, v_lower, v_upper
    );
    EXECUTE format(
        'CREATE TRIGGER security_mutation_audit_truncate_guard '
        'BEFORE TRUNCATE ON mtmf.%I FOR EACH STATEMENT '
        'EXECUTE FUNCTION mtmf.guard_security_mutation_audit()',
        v_child
    );
    EXECUTE format('ALTER TABLE mtmf.%I OWNER TO mtmf_owner', v_child);
    EXECUTE format('REVOKE ALL ON TABLE mtmf.%I FROM PUBLIC', v_child);
    EXECUTE format('REVOKE ALL ON TABLE mtmf.%I FROM mtmf_runtime', v_child);
END;
$$;
