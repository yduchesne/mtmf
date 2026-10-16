-- v014: Application onboarding entitlement functions (PR 22).
--
-- All functions are owner-owned, SECURITY INVOKER, with a fixed empty
-- search_path and schema-qualified references. None is granted to
-- mtmf_runtime. The write functions are the operator/installation-only
-- primitives; they do not create a Tenant and confer no authority.
--
-- Structural failures raise SQLSTATE MT046 (deterministic integrity).

-- ---------------------------------------------------------------------------
-- Guards (private; never runtime-granted).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION mtmf.guard_application_onboarding_entitlement()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT046',
            MESSAGE = 'application_onboarding_entitlement: history is append-only; delete is not permitted';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.application_id IS DISTINCT FROM OLD.application_id
           OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
           OR NEW.granted_by_operator_principal_id IS DISTINCT FROM OLD.granted_by_operator_principal_id
           OR NEW.grant_reason IS DISTINCT FROM OLD.grant_reason
           OR NEW.quota_total IS DISTINCT FROM OLD.quota_total THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT046',
                MESSAGE = 'application_onboarding_entitlement: immutable grant/provenance columns cannot be updated';
        END IF;
        IF OLD.state = 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT046',
                MESSAGE = 'application_onboarding_entitlement: a REVOKED entitlement is terminal and cannot be updated';
        END IF;
        IF NEW.state IS DISTINCT FROM OLD.state
           AND NOT (OLD.state = 1 AND NEW.state = 2) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT046',
                MESSAGE = 'application_onboarding_entitlement: illegal lifecycle transition';
        END IF;
        IF NEW.quota_consumed < OLD.quota_consumed THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT046',
                MESSAGE = 'application_onboarding_entitlement: quota_consumed is monotonic';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER application_onboarding_entitlement_guard
    BEFORE UPDATE OR DELETE ON mtmf.application_onboarding_entitlement
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_application_onboarding_entitlement();

CREATE OR REPLACE FUNCTION mtmf.guard_application_onboarding_entitlement_event()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'MT046',
        MESSAGE = 'application_onboarding_entitlement_event: append-only history cannot be updated or deleted';
END;
$$;

CREATE TRIGGER application_onboarding_entitlement_event_guard
    BEFORE UPDATE OR DELETE ON mtmf.application_onboarding_entitlement_event
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_application_onboarding_entitlement_event();

-- ---------------------------------------------------------------------------
-- Operator-only entitlement mutations (never runtime-granted).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION mtmf.application_onboarding_entitlement_grant(
    id_value uuid,
    application_id_value uuid,
    operator_principal_id_value uuid,
    grant_reason_value text,
    quota_total_value bigint,
    correlation_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    application_lifecycle smallint;
BEGIN
    SELECT a.lifecycle
      INTO application_lifecycle
      FROM mtmf.application AS a
     WHERE a.id = application_id_value;
    IF application_lifecycle IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT046',
            MESSAGE = 'application_onboarding_entitlement: unknown Application';
    END IF;
    IF application_lifecycle <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT046',
            MESSAGE = 'application_onboarding_entitlement: the Application is not ACTIVE';
    END IF;
    IF grant_reason_value IS NULL OR length(btrim(grant_reason_value)) NOT BETWEEN 1 AND 512 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT046',
            MESSAGE = 'application_onboarding_entitlement: grant_reason must be bounded and non-empty';
    END IF;
    IF quota_total_value IS NULL OR quota_total_value <= 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT046',
            MESSAGE = 'application_onboarding_entitlement: quota_total must be a positive explicit limit';
    END IF;

    INSERT INTO mtmf.application_onboarding_entitlement (
        id, application_id, state, granted_at,
        granted_by_operator_principal_id, grant_reason,
        quota_total, quota_consumed, version
    ) VALUES (
        id_value, application_id_value, 1, now(),
        operator_principal_id_value, btrim(grant_reason_value),
        quota_total_value, 0, 0
    )
    ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    INSERT INTO mtmf.application_onboarding_entitlement_event (
        id, entitlement_id, event_type, occurred_at,
        operator_principal_id, correlation_id,
        old_state, new_state, reason
    ) VALUES (
        gen_random_uuid(), id_value, 1, now(),
        operator_principal_id_value, correlation_id_value,
        NULL, 1, btrim(grant_reason_value)
    );
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_onboarding_entitlement_revoke(
    id_value uuid,
    operator_principal_id_value uuid,
    revocation_reason_value text,
    correlation_id_value uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    current_state smallint;
BEGIN
    SELECT e.state
      INTO current_state
      FROM mtmf.application_onboarding_entitlement AS e
     WHERE e.id = id_value
     FOR UPDATE;
    IF current_state IS NULL THEN
        RETURN false;
    END IF;
    IF current_state <> 1 THEN
        RETURN false;
    END IF;
    IF revocation_reason_value IS NULL
       OR length(btrim(revocation_reason_value)) NOT BETWEEN 1 AND 512 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT046',
            MESSAGE = 'application_onboarding_entitlement: revocation_reason must be bounded and non-empty';
    END IF;

    UPDATE mtmf.application_onboarding_entitlement
       SET state = 2,
           revoked_at = now(),
           revoked_by_operator_principal_id = operator_principal_id_value,
           revocation_reason = btrim(revocation_reason_value),
           version = version + 1
     WHERE id = id_value;

    INSERT INTO mtmf.application_onboarding_entitlement_event (
        id, entitlement_id, event_type, occurred_at,
        operator_principal_id, correlation_id,
        old_state, new_state, reason
    ) VALUES (
        gen_random_uuid(), id_value, 2, now(),
        operator_principal_id_value, correlation_id_value,
        1, 2, btrim(revocation_reason_value)
    );
    RETURN true;
END;
$$;

-- ---------------------------------------------------------------------------
-- Operator-only reads (never runtime-granted in PR 22).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION mtmf.application_onboarding_entitlement_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_id', application_id,
        'state', state,
        'granted_at', granted_at,
        'granted_by_operator_principal_id', granted_by_operator_principal_id,
        'grant_reason', grant_reason,
        'quota_total', quota_total,
        'quota_consumed', quota_consumed,
        'version', version,
        'revoked_at', revoked_at,
        'revoked_by_operator_principal_id', revoked_by_operator_principal_id,
        'revocation_reason', revocation_reason
    )
    FROM mtmf.application_onboarding_entitlement
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_onboarding_entitlement_find_by_application(
    application_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_id', application_id,
        'state', state,
        'granted_at', granted_at,
        'granted_by_operator_principal_id', granted_by_operator_principal_id,
        'grant_reason', grant_reason,
        'quota_total', quota_total,
        'quota_consumed', quota_consumed,
        'version', version,
        'revoked_at', revoked_at,
        'revoked_by_operator_principal_id', revoked_by_operator_principal_id,
        'revocation_reason', revocation_reason
    )
    FROM mtmf.application_onboarding_entitlement
    WHERE application_id = application_id_value
    ORDER BY granted_at, id;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_onboarding_entitlement_event_find_by_entitlement(
    entitlement_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'entitlement_id', entitlement_id,
        'event_type', event_type,
        'occurred_at', occurred_at,
        'operator_principal_id', operator_principal_id,
        'correlation_id', correlation_id,
        'old_state', old_state,
        'new_state', new_state,
        'reason', reason
    )
    FROM mtmf.application_onboarding_entitlement_event
    WHERE entitlement_id = entitlement_id_value
    ORDER BY occurred_at, id;
$$;
