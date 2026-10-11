-- v010: Application-registry guards, privileged mutation, and runtime reads.
--
-- Privileged mutation functions are owner-owned, SECURITY INVOKER, pin
-- ``search_path = ''`` and are NEVER granted to mtmf_runtime (decisions
-- S5/S8). The runtime read functions are narrowly reviewed SECURITY
-- DEFINER entry points with a fixed empty search_path; they return
-- detached JSON only.
--
-- Guard triggers enforce immutability, lifecycle-transition legality, and
-- the PR 13-1 A1 end-date amendment policy independently of the application,
-- so an accidental direct owner UPDATE cannot silently overwrite a
-- security-relevant transition (decision S2). This is the authoritative
-- last line of defense for concurrent writers: the trigger compares
-- ``NEW.ends_at`` to the locked row's ``OLD.ends_at``. Time-based expiry is
-- enforced by the pure eligibility evaluator plus the ``ends_at`` window; no
-- asynchronous status transition is required (decision S7).

-- ---------------------------------------------------------------------------
-- Structural immutability + lifecycle transition guards.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION mtmf.guard_application_registry_application()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.application_key IS DISTINCT FROM OLD.application_key
           OR NEW.owner_identity_id IS DISTINCT FROM OLD.owner_identity_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT043',
                MESSAGE = 'application: immutable identity/key/provenance columns cannot be updated';
        END IF;
        IF OLD.lifecycle = 3 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT040',
                MESSAGE = 'application: a RETIRED Application is terminal and cannot be updated';
        END IF;
        IF NEW.lifecycle IS DISTINCT FROM OLD.lifecycle
           AND NOT (
               (OLD.lifecycle = 1 AND NEW.lifecycle IN (2, 3))
               OR (OLD.lifecycle = 2 AND NEW.lifecycle IN (1, 3))
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT040',
                MESSAGE = 'application: illegal lifecycle transition';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER application_registry_application_guard
    BEFORE UPDATE ON mtmf.application
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_application_registry_application();

CREATE OR REPLACE FUNCTION mtmf.guard_application_tenant_registration()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.application_id IS DISTINCT FROM OLD.application_id
           OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.created_by_identity_id IS DISTINCT FROM OLD.created_by_identity_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT043',
                MESSAGE = 'application_tenant_registration: immutable columns cannot be updated';
        END IF;
        IF OLD.lifecycle = 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT041',
                MESSAGE = 'application_tenant_registration: a REVOKED registration is terminal and cannot be updated';
        END IF;
        IF NEW.lifecycle IS DISTINCT FROM OLD.lifecycle
           AND NOT (OLD.lifecycle = 1 AND NEW.lifecycle = 2) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT041',
                MESSAGE = 'application_tenant_registration: illegal lifecycle transition';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER application_tenant_registration_guard
    BEFORE UPDATE ON mtmf.application_tenant_registration
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_application_tenant_registration();

CREATE OR REPLACE FUNCTION mtmf.guard_tenant_application_subscription()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.application_id IS DISTINCT FROM OLD.application_id
           OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.created_by_identity_id IS DISTINCT FROM OLD.created_by_identity_id
           OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT043',
                MESSAGE = 'tenant_application_subscription: immutable columns cannot be updated';
        END IF;
        IF OLD.lifecycle IN (3, 4) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT042',
                MESSAGE = 'tenant_application_subscription: a terminal subscription cannot be updated';
        END IF;
        IF NEW.lifecycle IS DISTINCT FROM OLD.lifecycle
           AND NOT (
               (OLD.lifecycle = 0 AND NEW.lifecycle IN (1, 3))
               OR (OLD.lifecycle = 1 AND NEW.lifecycle IN (2, 3, 4))
               OR (OLD.lifecycle = 2 AND NEW.lifecycle IN (1, 3, 4))
           ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT042',
                MESSAGE = 'tenant_application_subscription: illegal lifecycle transition';
        END IF;
        -- A1: ``ends_at`` is restrictive only. It may be shortened or set on
        -- an open-ended subscription, but never extended, replaced with a
        -- later instant, or cleared to NULL.
        IF NEW.ends_at IS DISTINCT FROM OLD.ends_at THEN
            IF NEW.ends_at IS NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'MT042',
                    MESSAGE = 'tenant_application_subscription: a finite ends_at cannot be cleared';
            END IF;
            IF NEW.ends_at <= OLD.starts_at THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'MT042',
                    MESSAGE = 'tenant_application_subscription: an amended ends_at must be after starts_at';
            END IF;
            IF OLD.ends_at IS NOT NULL AND NEW.ends_at >= OLD.ends_at THEN
                RAISE EXCEPTION USING
                    ERRCODE = 'MT042',
                    MESSAGE = 'tenant_application_subscription: ends_at may only be shortened to a strictly earlier instant';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenant_application_subscription_guard
    BEFORE UPDATE ON mtmf.tenant_application_subscription
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_tenant_application_subscription();

-- ---------------------------------------------------------------------------
-- Privileged mutation (operator/installation only; never runtime-granted).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION mtmf.application_add(
    id_value uuid,
    application_key_value text,
    name_value text,
    owner_identity_id_value uuid,
    lifecycle_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    normalized_key text;
BEGIN
    normalized_key := lower(btrim(application_key_value));
    IF normalized_key !~ '^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT043',
            MESSAGE = 'application: application key is not a valid normalized key';
    END IF;
    INSERT INTO mtmf.application (
        id, application_key, name, owner_identity_id, lifecycle, extension
    ) VALUES (
        id_value, normalized_key, name_value, owner_identity_id_value,
        lifecycle_value, extension_value
    )
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_save(
    id_value uuid,
    name_value text,
    lifecycle_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    UPDATE mtmf.application
       SET name = name_value,
           lifecycle = lifecycle_value,
           extension = extension_value
     WHERE id = id_value;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_tenant_registration_add(
    id_value uuid,
    application_id_value uuid,
    tenant_id_value uuid,
    created_by_identity_id_value uuid,
    lifecycle_value smallint,
    created_at_value timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.application_tenant_registration (
        id, application_id, tenant_id, created_by_identity_id, lifecycle, created_at
    ) VALUES (
        id_value, application_id_value, tenant_id_value,
        created_by_identity_id_value, lifecycle_value, created_at_value
    )
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_tenant_registration_save(
    id_value uuid,
    lifecycle_value smallint
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    UPDATE mtmf.application_tenant_registration
       SET lifecycle = lifecycle_value
     WHERE id = id_value;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_application_subscription_add(
    id_value uuid,
    application_id_value uuid,
    tenant_id_value uuid,
    created_by_identity_id_value uuid,
    lifecycle_value smallint,
    starts_at_value timestamptz,
    ends_at_value timestamptz,
    created_at_value timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF ends_at_value IS NOT NULL AND ends_at_value <= starts_at_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT042',
            MESSAGE = 'tenant_application_subscription: ends_at must be after starts_at';
    END IF;
    INSERT INTO mtmf.tenant_application_subscription (
        id, application_id, tenant_id, created_by_identity_id, lifecycle,
        starts_at, ends_at, created_at
    ) VALUES (
        id_value, application_id_value, tenant_id_value,
        created_by_identity_id_value, lifecycle_value,
        starts_at_value, ends_at_value, created_at_value
    )
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_application_subscription_save(
    id_value uuid,
    lifecycle_value smallint,
    ends_at_value timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    UPDATE mtmf.tenant_application_subscription
       SET lifecycle = lifecycle_value,
           ends_at = ends_at_value
     WHERE id = id_value;
    RETURN FOUND;
END;
$$;

-- ---------------------------------------------------------------------------
-- Narrowly reviewed runtime reads (SECURITY DEFINER, detached JSON only).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION mtmf.application_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_key', application_key,
        'name', name,
        'owner_identity_id', owner_identity_id,
        'lifecycle', lifecycle,
        'extension', extension
    )
    FROM mtmf.application
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_get_by_key(application_key_value text)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_key', application_key,
        'name', name,
        'owner_identity_id', owner_identity_id,
        'lifecycle', lifecycle,
        'extension', extension
    )
    FROM mtmf.application
    WHERE application_key = lower(btrim(application_key_value));
$$;

CREATE OR REPLACE FUNCTION mtmf.application_tenant_registration_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_id', application_id,
        'tenant_id', tenant_id,
        'created_by_identity_id', created_by_identity_id,
        'lifecycle', lifecycle,
        'created_at', created_at
    )
    FROM mtmf.application_tenant_registration
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_tenant_registration_find_by_application_and_tenant(
    application_id_value uuid,
    tenant_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_id', application_id,
        'tenant_id', tenant_id,
        'created_by_identity_id', created_by_identity_id,
        'lifecycle', lifecycle,
        'created_at', created_at
    )
    FROM mtmf.application_tenant_registration
    WHERE application_id = application_id_value
      AND tenant_id = tenant_id_value
    ORDER BY created_at, id;
$$;

CREATE OR REPLACE FUNCTION mtmf.application_tenant_registration_find_by_tenant(tenant_id_value uuid)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_id', application_id,
        'tenant_id', tenant_id,
        'created_by_identity_id', created_by_identity_id,
        'lifecycle', lifecycle,
        'created_at', created_at
    )
    FROM mtmf.application_tenant_registration
    WHERE tenant_id = tenant_id_value
    ORDER BY created_at, id;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_application_subscription_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_id', application_id,
        'tenant_id', tenant_id,
        'created_by_identity_id', created_by_identity_id,
        'lifecycle', lifecycle,
        'starts_at', starts_at,
        'ends_at', ends_at,
        'created_at', created_at
    )
    FROM mtmf.tenant_application_subscription
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_application_subscription_find_by_application_and_tenant(
    application_id_value uuid,
    tenant_id_value uuid
)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_id', application_id,
        'tenant_id', tenant_id,
        'created_by_identity_id', created_by_identity_id,
        'lifecycle', lifecycle,
        'starts_at', starts_at,
        'ends_at', ends_at,
        'created_at', created_at
    )
    FROM mtmf.tenant_application_subscription
    WHERE application_id = application_id_value
      AND tenant_id = tenant_id_value
    ORDER BY created_at, id;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_application_subscription_find_by_tenant(tenant_id_value uuid)
RETURNS SETOF jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'application_id', application_id,
        'tenant_id', tenant_id,
        'created_by_identity_id', created_by_identity_id,
        'lifecycle', lifecycle,
        'starts_at', starts_at,
        'ends_at', ends_at,
        'created_at', created_at
    )
    FROM mtmf.tenant_application_subscription
    WHERE tenant_id = tenant_id_value
    ORDER BY created_at, id;
$$;
