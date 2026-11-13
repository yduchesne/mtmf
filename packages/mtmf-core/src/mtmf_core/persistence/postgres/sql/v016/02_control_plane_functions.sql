-- v016: PR 24P private control functions.
--
-- All five are owner-owned SECURITY DEFINER with an empty search_path. The
-- migration installs them without any mtmf_control_exec dependency; the
-- separate installation phase grants the five EXECUTEs.

CREATE OR REPLACE FUNCTION mtmf.pr24p_require_operator(
    operator_identity_id_value uuid,
    operator_principal_id_value uuid,
    operator_issuer_value text,
    operator_subject_value text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    assignment_id_value uuid;
    identity_record record;
    principal_record record;
    root_record record;
BEGIN
    IF operator_identity_id_value IS NULL OR operator_principal_id_value IS NULL
       OR operator_identity_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR operator_principal_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR operator_issuer_value IS NULL OR operator_subject_value IS NULL
       OR length(btrim(operator_issuer_value)) = 0
       OR length(btrim(operator_subject_value)) = 0
       OR length(operator_issuer_value) > 512
       OR length(operator_subject_value) > 512 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: malformed operator/target input';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM mtmf.external_subject_identity AS b
         WHERE b.issuer = operator_issuer_value
           AND b.subject = operator_subject_value
           AND b.identity_id = operator_identity_id_value
           AND b.lifecycle = 1
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: operator binding is not active for the claimed actor';
    END IF;

    SELECT * INTO identity_record FROM mtmf.identity AS i
     WHERE i.id = operator_identity_id_value;
    IF NOT FOUND OR identity_record.principal_id <> operator_principal_id_value
       OR identity_record.origin <> 2 OR identity_record.deletion_status <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: operator Identity is not active FEDERATED for the claimed Principal';
    END IF;
    SELECT * INTO principal_record FROM mtmf.principal AS p
     WHERE p.id = operator_principal_id_value;
    IF NOT FOUND OR principal_record.deletion_status <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: operator Principal is not active';
    END IF;
    SELECT * INTO root_record FROM mtmf.root_registry LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: canonical root registry is not initialized';
    END IF;
    IF identity_record.id = root_record.root_identity_id
       OR principal_record.id = root_record.root_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: canonical root is not an operator';
    END IF;

    SELECT a.id INTO assignment_id_value
      FROM mtmf.system_operator_assignment AS a
     WHERE a.identity_id = operator_identity_id_value
       AND a.principal_id = operator_principal_id_value
       AND a.role_urn = 'urn:mtmf:iam:roles:system:application-administrator'
       AND a.state = 1
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: no ACTIVE approved SYSTEM operator assignment';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM mtmf.builtin_role AS br
         WHERE br.role_urn = 'urn:mtmf:iam:roles:system:application-administrator'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: approved SYSTEM Role is not a protected builtin';
    END IF;
    RETURN assignment_id_value;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.pr24p_require_exact_permission(permission_urn_value text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM mtmf.permission_set AS ps
          JOIN mtmf.permission AS p ON p.permission_set_id = ps.id
         WHERE ps.role_urn = 'urn:mtmf:iam:roles:system:application-administrator'
           AND ps.effect = 'allow'
           AND p.urn = permission_urn_value
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: exact Action is not granted by the approved Role';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.pr24p_entitlement_json(entitlement_id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
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
    WHERE id = entitlement_id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.control_operator_authorization_snapshot(
    operator_identity_id_value uuid,
    operator_principal_id_value uuid,
    operator_issuer_value text,
    operator_subject_value text,
    application_id_value uuid,
    entitlement_id_value uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    assignment_id_value uuid;
    binding_record record;
    role_record record;
    sets_json jsonb;
    permissions_json jsonb;
    target_kind text;
BEGIN
    IF application_id_value IS NULL
       OR application_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR (entitlement_id_value IS NOT NULL
           AND entitlement_id_value = '00000000-0000-0000-0000-000000000000'::uuid) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: malformed snapshot target';
    END IF;
    assignment_id_value := mtmf.pr24p_require_operator(
        operator_identity_id_value,
        operator_principal_id_value,
        operator_issuer_value,
        operator_subject_value
    );

    SELECT * INTO binding_record FROM mtmf.external_subject_identity AS b
     WHERE b.issuer = operator_issuer_value AND b.subject = operator_subject_value
       AND b.lifecycle = 1;
    SELECT r.urn, r.name, r.description, r.defining_tenant_id
      INTO role_record
      FROM mtmf.role AS r
     WHERE r.urn = 'urn:mtmf:iam:roles:system:application-administrator'
       AND r.defining_tenant_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: approved SYSTEM Role definition is missing';
    END IF;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'id', ps.id,
               'role_urn', ps.role_urn,
               'effect', ps.effect,
               'position', ps.position
           ) ORDER BY ps.position, ps.id), '[]'::jsonb)
      INTO sets_json
      FROM mtmf.permission_set AS ps
     WHERE ps.role_urn = 'urn:mtmf:iam:roles:system:application-administrator';

    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'id', p.id,
               'permission_set_id', p.permission_set_id,
               'urn', p.urn,
               'position', p.position
           ) ORDER BY p.permission_set_id, p.position, p.id), '[]'::jsonb)
      INTO permissions_json
      FROM mtmf.permission AS p
      JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
     WHERE ps.role_urn = 'urn:mtmf:iam:roles:system:application-administrator';

    target_kind := CASE WHEN entitlement_id_value IS NULL THEN 'APPLICATION' ELSE 'ENTITLEMENT' END;
    RETURN jsonb_build_object(
        'v', 1,
        'operator', jsonb_build_object(
            'identity', jsonb_build_object(
                'id', operator_identity_id_value,
                'principal_id', operator_principal_id_value,
                'origin', 2,
                'deletion_status', 2,
                'canonical_root', false
            ),
            'principal', jsonb_build_object(
                'id', operator_principal_id_value,
                'deletion_status', 2,
                'canonical_root', false
            ),
            'binding', jsonb_build_object(
                'id', binding_record.id,
                'issuer', binding_record.issuer,
                'subject', binding_record.subject,
                'identity_id', binding_record.identity_id,
                'lifecycle', 1
            )
        ),
        'assignment', jsonb_build_object(
            'id', assignment_id_value,
            'identity_id', operator_identity_id_value,
            'principal_id', operator_principal_id_value,
            'role_urn', 'urn:mtmf:iam:roles:system:application-administrator',
            'state', 1,
            'created_at', (SELECT a.created_at FROM mtmf.system_operator_assignment a WHERE a.id = assignment_id_value),
            'revoked_at', NULL
        ),
        'role', jsonb_build_object(
            'urn', role_record.urn,
            'name', role_record.name,
            'description', role_record.description,
            'defining_tenant_id', NULL,
            'builtin', true,
            'approved_role', true
        ),
        'permission_sets', sets_json,
        'permissions', permissions_json,
        'target', jsonb_build_object(
            'kind', target_kind,
            'application_id', application_id_value,
            'entitlement_id', entitlement_id_value
        ),
        'checked_at', now()
    );
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.control_entitlement_grant(
    operator_identity_id_value uuid,
    operator_principal_id_value uuid,
    operator_issuer_value text,
    operator_subject_value text,
    application_id_value uuid,
    entitlement_id_value uuid,
    quota_total_value bigint,
    reason_value text,
    operation_id_value uuid,
    request_fingerprint_value bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    existing_fingerprint bytea;
    existing_result jsonb;
    application_lifecycle smallint;
    entitlement_json jsonb;
    result_json jsonb;
BEGIN
    IF application_id_value IS NULL OR entitlement_id_value IS NULL
       OR application_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR entitlement_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR operation_id_value IS NULL
       OR operation_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR quota_total_value IS NULL OR quota_total_value <= 0
       OR reason_value IS NULL OR length(btrim(reason_value)) NOT BETWEEN 1 AND 512
       OR request_fingerprint_value IS NULL OR octet_length(request_fingerprint_value) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: malformed grant input';
    END IF;
    PERFORM mtmf.pr24p_require_operator(
        operator_identity_id_value, operator_principal_id_value,
        operator_issuer_value, operator_subject_value
    );
    PERFORM 1 FROM mtmf.identity WHERE id = operator_identity_id_value FOR SHARE;
    PERFORM 1 FROM mtmf.principal WHERE id = operator_principal_id_value FOR SHARE;
    PERFORM 1 FROM mtmf.external_subject_identity
        WHERE issuer = operator_issuer_value AND subject = operator_subject_value
          AND identity_id = operator_identity_id_value AND lifecycle = 1 FOR SHARE;
    PERFORM mtmf.pr24p_require_exact_permission(
        'urn:mtmf:iam:permissions:system:application-onboarding-entitlement:grant-object'
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(operator_identity_id_value::text || ':' || operation_id_value::text, 0)
    );
    SELECT e.request_fingerprint, e.result INTO existing_fingerprint, existing_result
      FROM mtmf.system_operator_execution AS e
     WHERE e.operator_identity_id = operator_identity_id_value
       AND e.operation_id = operation_id_value;
    IF FOUND THEN
        IF existing_fingerprint IS DISTINCT FROM request_fingerprint_value THEN
            RAISE EXCEPTION USING ERRCODE = 'MT051',
                MESSAGE = 'PR24P: replay fingerprint conflict';
        END IF;
        RETURN existing_result;
    END IF;

    SELECT a.lifecycle INTO application_lifecycle FROM mtmf.application AS a
     WHERE a.id = application_id_value FOR UPDATE;
    IF NOT FOUND OR application_lifecycle <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: Application is missing or not ACTIVE';
    END IF;

    IF NOT mtmf.application_onboarding_entitlement_grant(
        entitlement_id_value, application_id_value, operator_principal_id_value,
        btrim(reason_value), quota_total_value, operation_id_value
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT051',
            MESSAGE = 'PR24P: entitlement grant conflict';
    END IF;
    entitlement_json := mtmf.pr24p_entitlement_json(entitlement_id_value);
    result_json := jsonb_build_object(
        'v', 1,
        'operation_id', operation_id_value,
        'outcome', 'CREATED',
        'application_id', application_id_value,
        'entitlement_id', entitlement_id_value,
        'entitlement', entitlement_json
    );
    INSERT INTO mtmf.system_operator_execution (
        operator_identity_id, operation_id, operator_principal_id,
        request_fingerprint, operation, action_urn, application_id,
        entitlement_id, outcome, result, completed_at
    ) VALUES (
        operator_identity_id_value, operation_id_value, operator_principal_id_value,
        request_fingerprint_value, 'entitlement.grant',
        'urn:mtmf:iam:actions:system:application-onboarding-entitlement:grant-object',
        application_id_value, entitlement_id_value, 'CREATED', result_json, now()
    );
    INSERT INTO mtmf.system_operator_execution_audit (
        id, operator_identity_id, operation_id, operator_principal_id,
        action_urn, application_id, entitlement_id, old_state, new_state,
        outcome, executor_role, occurred_at
    ) VALUES (
        gen_random_uuid(), operator_identity_id_value, operation_id_value,
        operator_principal_id_value,
        'urn:mtmf:iam:actions:system:application-onboarding-entitlement:grant-object',
        application_id_value, entitlement_id_value, NULL, 1,
        'CREATED', 'mtmf_control_exec', now()
    );
    RETURN result_json;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.control_entitlement_revoke(
    operator_identity_id_value uuid,
    operator_principal_id_value uuid,
    operator_issuer_value text,
    operator_subject_value text,
    application_id_value uuid,
    entitlement_id_value uuid,
    reason_value text,
    operation_id_value uuid,
    request_fingerprint_value bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    existing_fingerprint bytea;
    existing_result jsonb;
    entitlement_record record;
    entitlement_json jsonb;
    result_json jsonb;
BEGIN
    IF application_id_value IS NULL OR entitlement_id_value IS NULL
       OR application_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR entitlement_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR operation_id_value IS NULL
       OR operation_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR reason_value IS NULL OR length(btrim(reason_value)) NOT BETWEEN 1 AND 512
       OR request_fingerprint_value IS NULL OR octet_length(request_fingerprint_value) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: malformed revoke input';
    END IF;
    PERFORM mtmf.pr24p_require_operator(
        operator_identity_id_value, operator_principal_id_value,
        operator_issuer_value, operator_subject_value
    );
    PERFORM 1 FROM mtmf.identity WHERE id = operator_identity_id_value FOR SHARE;
    PERFORM 1 FROM mtmf.principal WHERE id = operator_principal_id_value FOR SHARE;
    PERFORM 1 FROM mtmf.external_subject_identity
        WHERE issuer = operator_issuer_value AND subject = operator_subject_value
          AND identity_id = operator_identity_id_value AND lifecycle = 1 FOR SHARE;
    PERFORM mtmf.pr24p_require_exact_permission(
        'urn:mtmf:iam:permissions:system:application-onboarding-entitlement:revoke-object'
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(operator_identity_id_value::text || ':' || operation_id_value::text, 0)
    );
    SELECT e.request_fingerprint, e.result INTO existing_fingerprint, existing_result
      FROM mtmf.system_operator_execution AS e
     WHERE e.operator_identity_id = operator_identity_id_value
       AND e.operation_id = operation_id_value;
    IF FOUND THEN
        IF existing_fingerprint IS DISTINCT FROM request_fingerprint_value THEN
            RAISE EXCEPTION USING ERRCODE = 'MT051',
                MESSAGE = 'PR24P: replay fingerprint conflict';
        END IF;
        RETURN existing_result;
    END IF;

    SELECT e.application_id, e.state INTO entitlement_record
      FROM mtmf.application_onboarding_entitlement AS e
     WHERE e.id = entitlement_id_value FOR UPDATE;
    IF NOT FOUND OR entitlement_record.application_id <> application_id_value THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: entitlement target is missing or unrelated';
    END IF;
    IF entitlement_record.state = 2 THEN
        entitlement_json := mtmf.pr24p_entitlement_json(entitlement_id_value);
        RETURN jsonb_build_object(
            'v', 1, 'operation_id', operation_id_value, 'outcome', 'NO_OP',
            'application_id', application_id_value,
            'entitlement_id', entitlement_id_value,
            'entitlement', entitlement_json
        );
    END IF;
    IF NOT mtmf.application_onboarding_entitlement_revoke(
        entitlement_id_value, operator_principal_id_value,
        btrim(reason_value), operation_id_value
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT051',
            MESSAGE = 'PR24P: entitlement revoke conflict';
    END IF;
    entitlement_json := mtmf.pr24p_entitlement_json(entitlement_id_value);
    result_json := jsonb_build_object(
        'v', 1, 'operation_id', operation_id_value, 'outcome', 'REVOKED',
        'application_id', application_id_value,
        'entitlement_id', entitlement_id_value,
        'entitlement', entitlement_json
    );
    INSERT INTO mtmf.system_operator_execution (
        operator_identity_id, operation_id, operator_principal_id,
        request_fingerprint, operation, action_urn, application_id,
        entitlement_id, outcome, result, completed_at
    ) VALUES (
        operator_identity_id_value, operation_id_value, operator_principal_id_value,
        request_fingerprint_value, 'entitlement.revoke',
        'urn:mtmf:iam:actions:system:application-onboarding-entitlement:revoke-object',
        application_id_value, entitlement_id_value, 'REVOKED', result_json, now()
    );
    INSERT INTO mtmf.system_operator_execution_audit (
        id, operator_identity_id, operation_id, operator_principal_id,
        action_urn, application_id, entitlement_id, old_state, new_state,
        outcome, executor_role, occurred_at
    ) VALUES (
        gen_random_uuid(), operator_identity_id_value, operation_id_value,
        operator_principal_id_value,
        'urn:mtmf:iam:actions:system:application-onboarding-entitlement:revoke-object',
        application_id_value, entitlement_id_value, 1, 2,
        'REVOKED', 'mtmf_control_exec', now()
    );
    RETURN result_json;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.control_entitlement_get(
    operator_identity_id_value uuid,
    operator_principal_id_value uuid,
    operator_issuer_value text,
    operator_subject_value text,
    application_id_value uuid,
    entitlement_id_value uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    entitlement_record record;
    entitlement_json jsonb;
BEGIN
    IF application_id_value IS NULL OR entitlement_id_value IS NULL
       OR application_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR entitlement_id_value = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: malformed get target';
    END IF;
    PERFORM mtmf.pr24p_require_operator(
        operator_identity_id_value, operator_principal_id_value,
        operator_issuer_value, operator_subject_value
    );
    PERFORM mtmf.pr24p_require_exact_permission(
        'urn:mtmf:iam:permissions:system:application-onboarding-entitlement:get-object'
    );
    SELECT e.application_id, e.state INTO entitlement_record
      FROM mtmf.application_onboarding_entitlement AS e
     WHERE e.id = entitlement_id_value;
    IF NOT FOUND OR entitlement_record.application_id <> application_id_value THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: entitlement target is missing or unrelated';
    END IF;
    entitlement_json := mtmf.pr24p_entitlement_json(entitlement_id_value);
    RETURN jsonb_build_object(
        'v', 1, 'outcome', 'FOUND',
        'application_id', application_id_value,
        'entitlement_id', entitlement_id_value,
        'entitlement', entitlement_json
    );
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.control_pre_tenant_admission_read(
    application_id_value uuid,
    issuer_value text,
    subject_value text
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    application_lifecycle smallint;
    active_count integer;
    revoked_count integer;
    binding_record record;
    identity_record record;
    principal_record record;
    root_record record;
    active_entitlement_count integer;
    entitlement_record record;
BEGIN
    IF application_id_value IS NULL
       OR application_id_value = '00000000-0000-0000-0000-000000000000'::uuid
       OR issuer_value IS NULL OR subject_value IS NULL
       OR length(btrim(issuer_value)) = 0 OR length(btrim(subject_value)) = 0
       OR length(issuer_value) > 512 OR length(subject_value) > 512 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: malformed admission input';
    END IF;
    SELECT a.lifecycle INTO application_lifecycle FROM mtmf.application AS a
     WHERE a.id = application_id_value;
    IF NOT FOUND OR application_lifecycle <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'PR24P: Application is missing or not ACTIVE';
    END IF;

    SELECT count(*) FILTER (WHERE lifecycle = 1),
           count(*) FILTER (WHERE lifecycle = 2)
      INTO active_count, revoked_count
      FROM mtmf.external_subject_identity
     WHERE issuer = issuer_value AND subject = subject_value;

    IF active_count > 1 THEN
        RETURN jsonb_build_object('v', 1, 'subject_history', 'CONFLICT',
                                  'entitlement_id', NULL, 'quota_available', false);
    END IF;
    IF active_count = 1 THEN
        SELECT * INTO binding_record FROM mtmf.external_subject_identity
         WHERE issuer = issuer_value AND subject = subject_value AND lifecycle = 1;
        SELECT * INTO identity_record FROM mtmf.identity WHERE id = binding_record.identity_id;
        SELECT * INTO principal_record FROM mtmf.principal
         WHERE id = identity_record.principal_id;
        SELECT * INTO root_record FROM mtmf.root_registry LIMIT 1;
        IF NOT FOUND OR root_record.root_identity_id IS NULL
           OR identity_record.id IS NULL OR principal_record.id IS NULL
           OR identity_record.origin <> 2 OR identity_record.deletion_status <> 2
           OR principal_record.deletion_status <> 2
           OR identity_record.id = root_record.root_identity_id
           OR principal_record.id = root_record.root_principal_id THEN
            RETURN jsonb_build_object('v', 1, 'subject_history', 'CONFLICT',
                                      'entitlement_id', NULL, 'quota_available', false);
        END IF;
        RETURN jsonb_build_object('v', 1, 'subject_history', 'ACTIVE',
                                  'entitlement_id', NULL, 'quota_available', false);
    END IF;
    IF revoked_count > 0 THEN
        RETURN jsonb_build_object('v', 1, 'subject_history', 'REVOKED_ONLY',
                                  'entitlement_id', NULL, 'quota_available', false);
    END IF;

    SELECT count(*) INTO active_entitlement_count
      FROM mtmf.application_onboarding_entitlement
     WHERE application_id = application_id_value AND state = 1;
    IF active_entitlement_count > 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT050',
            MESSAGE = 'PR24P: corrupt multiple ACTIVE entitlements';
    END IF;
    IF active_entitlement_count = 0 THEN
        RETURN jsonb_build_object('v', 1, 'subject_history', 'NEVER_SEEN',
                                  'entitlement_id', NULL, 'quota_available', false);
    END IF;
    SELECT * INTO entitlement_record FROM mtmf.application_onboarding_entitlement
     WHERE application_id = application_id_value AND state = 1;
    IF entitlement_record.quota_consumed < entitlement_record.quota_total THEN
        RETURN jsonb_build_object('v', 1, 'subject_history', 'NEVER_SEEN',
                                  'entitlement_id', entitlement_record.id,
                                  'quota_available', true);
    END IF;
    RETURN jsonb_build_object('v', 1, 'subject_history', 'NEVER_SEEN',
                              'entitlement_id', NULL, 'quota_available', false);
END;
$$;
