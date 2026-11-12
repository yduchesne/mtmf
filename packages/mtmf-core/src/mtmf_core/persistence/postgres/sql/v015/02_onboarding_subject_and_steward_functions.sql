-- v015: PR 23 owner-only, non-committing onboarding transaction participants.
--
-- Both functions are SECURITY INVOKER, owned by mtmf_owner, pin an empty
-- search_path, schema-qualify every object reference, and are NEVER granted to
-- mtmf_runtime. Their arguments are DATA, not authentication evidence; the
-- future PR 24P/22B privileged coordinator must independently verify the
-- token proof and bind these values to its own single transaction.
--
-- Neither function creates/activates a Tenant, consumes quota, persists replay,
-- writes a registration/subscription, or commits. Any failure aborts the
-- statement and the caller's whole transaction.
--
-- SQLSTATE contract:
--   MT047 — malformed/unacceptable PR 23 input or structural eligibility;
--   MT048 — existing-subject conflict, revoked-only key, dirty new-Tenant
--           graph, or concurrency conflict.

-- ---------------------------------------------------------------------------
-- B1: global subject resolution/creation (no Tenant side effects).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION mtmf.onboarding_subject_prepare(
    issuer_value text,
    subject_value text,
    new_principal_id_value uuid,
    new_identity_id_value uuid,
    new_binding_id_value uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    root_record record;
    active_binding record;
    identity_record record;
    principal_record record;
    active_count integer;
    revoked_count integer;
BEGIN
    -- Exact, case-sensitive, opaque issuer/subject values. They are never
    -- trimmed, lowercased or otherwise normalized for identity matching.
    IF issuer_value IS NULL OR subject_value IS NULL
       OR pg_catalog.length(pg_catalog.btrim(issuer_value)) = 0
       OR pg_catalog.length(pg_catalog.btrim(subject_value)) = 0
       OR pg_catalog.length(issuer_value) > 512
       OR pg_catalog.length(subject_value) > 512 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_subject_prepare: issuer and subject must be bounded, non-empty exact text';
    END IF;

    IF new_principal_id_value IS NULL
       OR new_identity_id_value IS NULL
       OR new_binding_id_value IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_subject_prepare: all target UUIDs are required';
    END IF;
    IF new_principal_id_value = new_identity_id_value
       OR new_principal_id_value = new_binding_id_value
       OR new_identity_id_value = new_binding_id_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_subject_prepare: target UUIDs must be pairwise distinct';
    END IF;

    SELECT * INTO root_record FROM mtmf.root_registry WHERE singleton;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_subject_prepare: the canonical root registry is not initialized';
    END IF;
    IF new_principal_id_value = root_record.root_principal_id
       OR new_identity_id_value = root_record.root_identity_id THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_subject_prepare: target UUIDs must not be the canonical root objects';
    END IF;

    -- Same-key race serialization aid only; the partial unique index and the
    -- explicit conflict checks remain authoritative.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'mtmf.pr23.subject:' || issuer_value || pg_catalog.chr(31) || subject_value,
            0
        )
    );

    PERFORM 1
      FROM mtmf.external_subject_identity
     WHERE issuer = issuer_value AND subject = subject_value
     ORDER BY id
     FOR UPDATE;

    SELECT count(*) FILTER (WHERE lifecycle = 1),
           count(*) FILTER (WHERE lifecycle = 2)
      INTO active_count, revoked_count
      FROM mtmf.external_subject_identity
     WHERE issuer = issuer_value AND subject = subject_value;

    IF active_count > 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT048',
            MESSAGE = 'onboarding_subject_prepare: ambiguous multiple ACTIVE subject bindings';
    END IF;

    IF active_count = 1 THEN
        SELECT * INTO active_binding
          FROM mtmf.external_subject_identity
         WHERE issuer = issuer_value AND subject = subject_value AND lifecycle = 1;

        SELECT * INTO identity_record
          FROM mtmf.identity WHERE id = active_binding.identity_id;
        IF NOT FOUND
           OR identity_record.origin <> 2
           OR identity_record.deletion_status <> 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT048',
                MESSAGE = 'onboarding_subject_prepare: the bound Identity is missing, deleted or not FEDERATED';
        END IF;

        SELECT * INTO principal_record
          FROM mtmf.principal WHERE id = identity_record.principal_id;
        IF NOT FOUND OR principal_record.deletion_status <> 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT048',
                MESSAGE = 'onboarding_subject_prepare: the bound Principal is missing or deleted';
        END IF;

        IF identity_record.id = root_record.root_identity_id
           OR principal_record.id = root_record.root_principal_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT047',
                MESSAGE = 'onboarding_subject_prepare: the canonical root subject is never returned';
        END IF;

        RETURN pg_catalog.jsonb_build_object(
            'status', 'EXISTING',
            'identity_id', identity_record.id,
            'principal_id', principal_record.id
        );
    END IF;

    -- No ACTIVE binding. Revoked history is terminal evidence, never absence.
    IF revoked_count > 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT048',
            MESSAGE = 'onboarding_subject_prepare: the subject key has only revoked history and requires an explicit rebind decision';
    END IF;

    IF EXISTS (SELECT 1 FROM mtmf.principal WHERE id = new_principal_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.identity WHERE id = new_identity_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.external_subject_identity WHERE id = new_binding_id_value) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT048',
            MESSAGE = 'onboarding_subject_prepare: a supplied target UUID is already in use';
    END IF;

    INSERT INTO mtmf.principal (id, name, deletion_status)
    VALUES (new_principal_id_value, 'Onboarded Principal', 2);

    INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status)
    VALUES (new_identity_id_value, new_principal_id_value, 'Onboarded Identity', 2, 2);

    INSERT INTO mtmf.external_subject_identity (
        id, issuer, subject, identity_id, lifecycle, created_at
    ) VALUES (
        new_binding_id_value, issuer_value, subject_value, new_identity_id_value, 1, pg_catalog.now()
    );

    RETURN pg_catalog.jsonb_build_object(
        'status', 'CREATED',
        'identity_id', new_identity_id_value,
        'principal_id', new_principal_id_value
    );
END;
$$;

-- ---------------------------------------------------------------------------
-- B2: strict first-steward attachment for a caller-created PROVISIONING Tenant.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION mtmf.onboarding_initial_steward_attach(
    tenant_id_value uuid,
    issuer_value text,
    subject_value text,
    identity_id_value uuid,
    assignment_id_value uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    tenant_record record;
    root_record record;
    binding_record record;
    identity_record record;
    principal_record record;
    principal_uuid uuid;
    inserted boolean;
    tenant_admin_urn constant text := 'urn:mtmf:iam:roles:system:tenant-administrator';
BEGIN
    IF tenant_id_value IS NULL OR identity_id_value IS NULL OR assignment_id_value IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: Tenant, Identity and assignment UUIDs are required';
    END IF;
    IF issuer_value IS NULL OR subject_value IS NULL
       OR pg_catalog.length(pg_catalog.btrim(issuer_value)) = 0
       OR pg_catalog.length(pg_catalog.btrim(subject_value)) = 0
       OR pg_catalog.length(issuer_value) > 512
       OR pg_catalog.length(subject_value) > 512 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: issuer and subject must be bounded, non-empty exact text';
    END IF;

    -- Lock order follows v008: Tenant, then Principal, then Identity, then the
    -- designation. The fresh Tenant must be ordinary, PROVISIONING, not deleted,
    -- owned by the supplied Identity, and distinct from canonical root.
    SELECT * INTO tenant_record FROM mtmf.tenant WHERE id = tenant_id_value FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: unknown Tenant';
    END IF;
    IF tenant_record.scope <> 2
       OR tenant_record.lifecycle <> 0
       OR tenant_record.deletion_status <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the Tenant is not a fresh ordinary PROVISIONING Tenant';
    END IF;
    IF tenant_record.owner_identity_id <> identity_id_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the Tenant owner Identity does not match the supplied Identity';
    END IF;

    SELECT * INTO root_record FROM mtmf.root_registry WHERE singleton;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the canonical root registry is not initialized';
    END IF;
    IF tenant_id_value = root_record.root_tenant_id THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the canonical root Tenant is never eligible';
    END IF;

    -- The exact ACTIVE global subject must bind to the supplied Identity.
    SELECT * INTO binding_record
      FROM mtmf.external_subject_identity
     WHERE issuer = issuer_value AND subject = subject_value AND lifecycle = 1
     FOR UPDATE;
    IF NOT FOUND OR binding_record.identity_id <> identity_id_value THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: no exact ACTIVE subject binding identifies the supplied Identity';
    END IF;

    SELECT i.principal_id INTO principal_uuid FROM mtmf.identity AS i WHERE i.id = identity_id_value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the supplied Identity does not exist';
    END IF;

    SELECT * INTO principal_record FROM mtmf.principal WHERE id = principal_uuid FOR UPDATE;
    IF NOT FOUND OR principal_record.deletion_status <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the Identity Principal is missing or deleted';
    END IF;

    SELECT * INTO identity_record FROM mtmf.identity WHERE id = identity_id_value FOR UPDATE;
    IF NOT FOUND
       OR identity_record.principal_id <> principal_uuid
       OR identity_record.origin <> 2
       OR identity_record.deletion_status <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the Identity is not an active FEDERATED Identity of its Principal';
    END IF;

    IF identity_record.id = root_record.root_identity_id
       OR principal_record.id = root_record.root_principal_id THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the canonical root subject can never be designated';
    END IF;

    -- A supposedly fresh Tenant must be empty. A nonempty graph is an integrity
    -- conflict, never an idempotent merge target.
    IF EXISTS (SELECT 1 FROM mtmf.stewardship_designation WHERE tenant_id = tenant_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.principal_tenant_membership WHERE tenant_id = tenant_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.identity_tenant_membership WHERE tenant_id = tenant_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.identity_role_assignment WHERE tenant_id = tenant_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.application_tenant_registration WHERE tenant_id = tenant_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.tenant_application_subscription WHERE tenant_id = tenant_id_value) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT048',
            MESSAGE = 'onboarding_initial_steward_attach: the new Tenant already contains stewardship, membership, Role, registration or subscription state';
    END IF;

    -- The protected built-in Tenant Administrator Role must already exist in the
    -- approved system catalog. It is never created, modified or globally granted.
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.role AS r
        WHERE r.urn = tenant_admin_urn AND r.defining_tenant_id IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM mtmf.builtin_role AS b WHERE b.role_urn = tenant_admin_urn
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT047',
            MESSAGE = 'onboarding_initial_steward_attach: the protected Tenant Administrator Role is missing from the approved system catalog';
    END IF;

    SELECT mtmf.principal_tenant_membership_add(principal_uuid, tenant_id_value) INTO inserted;
    IF inserted IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT048',
            MESSAGE = 'onboarding_initial_steward_attach: the Principal Tenant membership was not newly inserted';
    END IF;

    SELECT mtmf.identity_tenant_membership_add(identity_id_value, tenant_id_value) INTO inserted;
    IF inserted IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT048',
            MESSAGE = 'onboarding_initial_steward_attach: the Identity Tenant membership was not newly inserted';
    END IF;

    SELECT mtmf.identity_role_assignment_add(
        assignment_id_value, tenant_id_value, identity_id_value, tenant_admin_urn, NULL
    ) INTO inserted;
    IF inserted IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT048',
            MESSAGE = 'onboarding_initial_steward_attach: the Tenant Administrator assignment was not newly inserted';
    END IF;

    INSERT INTO mtmf.stewardship_designation (
        tenant_id, steward_principal_id, designated_identity_id, version
    ) VALUES (
        tenant_id_value, principal_uuid, identity_id_value, 1
    );

    -- Structural audit only: this function cannot attest the external operator,
    -- so it must not fabricate actor provenance. PR 22B owns the verified
    -- request-level operation/audit correlation.
    INSERT INTO mtmf.stewardship_audit (
        tenant_id, operation, previous_principal_id, new_principal_id,
        previous_identity_id, new_identity_id, actor_provenance, reason
    ) VALUES (
        tenant_id_value, 'INITIAL_ONBOARDING', NULL, principal_uuid,
        NULL, identity_id_value, NULL,
        'initial pre-Tenant stewardship; request audit pending PR22B'
    );

    RETURN pg_catalog.jsonb_build_object(
        'tenant_id', tenant_id_value,
        'principal_id', principal_uuid,
        'identity_id', identity_id_value,
        'assignment_id', assignment_id_value,
        'stewardship_version', 1
    );
END;
$$;
