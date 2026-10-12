-- v011: authentication binding guards, privileged mutation, and runtime reads.

CREATE OR REPLACE FUNCTION mtmf.guard_service_credential_application()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.issuer IS DISTINCT FROM OLD.issuer
           OR NEW.client_id IS DISTINCT FROM OLD.client_id
           OR NEW.application_id IS DISTINCT FROM OLD.application_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT043',
                MESSAGE = 'service_credential_application: immutable columns cannot be updated';
        END IF;
        IF OLD.lifecycle = 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT045',
                MESSAGE = 'service_credential_application: a REVOKED binding is terminal';
        END IF;
        IF NEW.lifecycle IS DISTINCT FROM OLD.lifecycle
           AND NOT (OLD.lifecycle = 1 AND NEW.lifecycle = 2) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT045',
                MESSAGE = 'service_credential_application: illegal lifecycle transition';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER service_credential_application_guard
    BEFORE UPDATE ON mtmf.service_credential_application
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_service_credential_application();

CREATE OR REPLACE FUNCTION mtmf.guard_external_subject_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.issuer IS DISTINCT FROM OLD.issuer
           OR NEW.subject IS DISTINCT FROM OLD.subject
           OR NEW.identity_id IS DISTINCT FROM OLD.identity_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT043',
                MESSAGE = 'external_subject_identity: immutable columns cannot be updated';
        END IF;
        IF OLD.lifecycle = 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT045',
                MESSAGE = 'external_subject_identity: a REVOKED binding is terminal';
        END IF;
        IF NEW.lifecycle IS DISTINCT FROM OLD.lifecycle
           AND NOT (OLD.lifecycle = 1 AND NEW.lifecycle = 2) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT045',
                MESSAGE = 'external_subject_identity: illegal lifecycle transition';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER external_subject_identity_guard
    BEFORE UPDATE ON mtmf.external_subject_identity
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_external_subject_identity();

CREATE OR REPLACE FUNCTION mtmf.service_credential_application_add(
    id_value uuid,
    issuer_value text,
    client_id_value text,
    application_id_value uuid,
    lifecycle_value smallint,
    created_at_value timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF length(btrim(issuer_value)) = 0 OR length(btrim(client_id_value)) = 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT044',
            MESSAGE = 'service_credential_application: issuer and client_id are required';
    END IF;
    INSERT INTO mtmf.service_credential_application (
        id, issuer, client_id, application_id, lifecycle, created_at
    ) VALUES (
        id_value, issuer_value, client_id_value, application_id_value, lifecycle_value, created_at_value
    )
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.service_credential_application_revoke(id_value uuid)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    UPDATE mtmf.service_credential_application
       SET lifecycle = 2
     WHERE id = id_value AND lifecycle = 1;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.external_subject_identity_add(
    id_value uuid,
    issuer_value text,
    subject_value text,
    identity_id_value uuid,
    lifecycle_value smallint,
    created_at_value timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF length(btrim(issuer_value)) = 0 OR length(btrim(subject_value)) = 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT044',
            MESSAGE = 'external_subject_identity: issuer and subject are required';
    END IF;
    INSERT INTO mtmf.external_subject_identity (
        id, issuer, subject, identity_id, lifecycle, created_at
    ) VALUES (
        id_value, issuer_value, subject_value, identity_id_value, lifecycle_value, created_at_value
    )
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.external_subject_identity_revoke(id_value uuid)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    UPDATE mtmf.external_subject_identity
       SET lifecycle = 2
     WHERE id = id_value AND lifecycle = 1;
    RETURN FOUND;
END;
$$;

-- Narrowly reviewed runtime reads (SECURITY DEFINER, detached JSON only).
CREATE OR REPLACE FUNCTION mtmf.service_credential_application_find_active(
    issuer_value text, client_id_value text
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'issuer', issuer,
        'client_id', client_id,
        'application_id', application_id,
        'lifecycle', lifecycle,
        'created_at', created_at
    )
    FROM mtmf.service_credential_application
    WHERE issuer = issuer_value AND client_id = client_id_value AND lifecycle = 1;
$$;

CREATE OR REPLACE FUNCTION mtmf.external_subject_identity_find_active(
    issuer_value text, subject_value text
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'issuer', issuer,
        'subject', subject,
        'identity_id', identity_id,
        'lifecycle', lifecycle,
        'created_at', created_at
    )
    FROM mtmf.external_subject_identity
    WHERE issuer = issuer_value AND subject = subject_value AND lifecycle = 1;
$$;
