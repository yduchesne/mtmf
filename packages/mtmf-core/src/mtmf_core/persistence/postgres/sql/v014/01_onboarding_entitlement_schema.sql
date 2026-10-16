-- v014: Application onboarding entitlement foundation (PR 22).
--
-- This is the safely isolated, operator-only persistence foundation for the
-- PR 21-approved pre-Tenant onboarding entitlement. It deliberately contains
-- NO Tenant-committing composite, NO runtime-granted mutation, and NO Role
-- grant for the admission-only identifier. The first-Tenant composite is
-- BLOCKED (see docs/pr-artifacts/pr-22/PR22_STOP_REPORT.md).
--
--   * ``application_onboarding_entitlement``       — per-Application grant,
--     keyed to the canonical registered Application UUID; ACTIVE (1) or
--     REVOKED (2); REVOKED is terminal; at most one ACTIVE row per Application.
--   * ``application_onboarding_entitlement_event`` — append-only grant/revoke
--     history with immutable provenance.
--
-- The entitlement is NOT a Role, Permission, subscription, or credential, and
-- confers no authority by itself. All mutation functions are owner-owned
-- SECURITY INVOKER and are never granted to mtmf_runtime.

CREATE TABLE mtmf.application_onboarding_entitlement (
    id uuid NOT NULL,
    application_id uuid NOT NULL,
    state smallint NOT NULL,
    granted_at timestamptz NOT NULL,
    granted_by_operator_principal_id uuid NOT NULL,
    grant_reason text NOT NULL,
    quota_total bigint NOT NULL,
    quota_consumed bigint NOT NULL DEFAULT 0,
    version bigint NOT NULL DEFAULT 0,
    revoked_at timestamptz NULL,
    revoked_by_operator_principal_id uuid NULL,
    revocation_reason text NULL,
    CONSTRAINT application_onboarding_entitlement_pk PRIMARY KEY (id),
    -- ACTIVE=1, REVOKED=2 (terminal).
    CONSTRAINT application_onboarding_entitlement_state_check CHECK (state IN (1, 2)),
    CONSTRAINT application_onboarding_entitlement_quota_total_check CHECK (quota_total > 0),
    CONSTRAINT application_onboarding_entitlement_quota_consumed_check CHECK (
        quota_consumed >= 0 AND quota_consumed <= quota_total
    ),
    CONSTRAINT application_onboarding_entitlement_version_check CHECK (version >= 0),
    CONSTRAINT application_onboarding_entitlement_grant_reason_check CHECK (
        length(btrim(grant_reason)) BETWEEN 1 AND 512
    ),
    CONSTRAINT application_onboarding_entitlement_revocation_reason_check CHECK (
        revocation_reason IS NULL OR length(btrim(revocation_reason)) BETWEEN 1 AND 512
    ),
    -- A REVOKED row carries complete revocation provenance; an ACTIVE row
    -- carries none. Partial revocation state is structurally impossible.
    CONSTRAINT application_onboarding_entitlement_revocation_consistency CHECK (
        (state = 2
            AND revoked_at IS NOT NULL
            AND revoked_by_operator_principal_id IS NOT NULL
            AND revocation_reason IS NOT NULL)
        OR (state = 1
            AND revoked_at IS NULL
            AND revoked_by_operator_principal_id IS NULL
            AND revocation_reason IS NULL)
    ),
    CONSTRAINT application_onboarding_entitlement_application_fk
        FOREIGN KEY (application_id) REFERENCES mtmf.application (id),
    CONSTRAINT application_onboarding_entitlement_granted_by_fk
        FOREIGN KEY (granted_by_operator_principal_id) REFERENCES mtmf.principal (id),
    CONSTRAINT application_onboarding_entitlement_revoked_by_fk
        FOREIGN KEY (revoked_by_operator_principal_id) REFERENCES mtmf.principal (id)
);

-- At most one ACTIVE entitlement per Application; REVOKED history never blocks
-- a fresh replacement grant (which receives a new UUID).
CREATE UNIQUE INDEX application_onboarding_entitlement_active_unique
    ON mtmf.application_onboarding_entitlement (application_id)
    WHERE state = 1;

CREATE INDEX application_onboarding_entitlement_application_idx
    ON mtmf.application_onboarding_entitlement (application_id);

CREATE TABLE mtmf.application_onboarding_entitlement_event (
    id uuid NOT NULL,
    entitlement_id uuid NOT NULL,
    event_type smallint NOT NULL,
    occurred_at timestamptz NOT NULL,
    operator_principal_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    old_state smallint NULL,
    new_state smallint NOT NULL,
    reason text NOT NULL,
    CONSTRAINT application_onboarding_entitlement_event_pk PRIMARY KEY (id),
    -- GRANTED=1, REVOKED=2.
    CONSTRAINT application_onboarding_entitlement_event_type_check CHECK (event_type IN (1, 2)),
    CONSTRAINT application_onboarding_entitlement_event_new_state_check CHECK (new_state IN (1, 2)),
    CONSTRAINT application_onboarding_entitlement_event_old_state_check CHECK (
        old_state IS NULL OR old_state IN (1, 2)
    ),
    -- GRANTED has no previous state and yields ACTIVE; REVOKED starts ACTIVE
    -- and yields REVOKED.
    CONSTRAINT application_onboarding_entitlement_event_shape_check CHECK (
        (event_type = 1 AND old_state IS NULL AND new_state = 1)
        OR (event_type = 2 AND old_state = 1 AND new_state = 2)
    ),
    CONSTRAINT application_onboarding_entitlement_event_reason_check CHECK (
        length(btrim(reason)) BETWEEN 1 AND 512
    ),
    CONSTRAINT application_onboarding_entitlement_event_entitlement_fk
        FOREIGN KEY (entitlement_id) REFERENCES mtmf.application_onboarding_entitlement (id),
    CONSTRAINT application_onboarding_entitlement_event_operator_fk
        FOREIGN KEY (operator_principal_id) REFERENCES mtmf.principal (id)
);

CREATE INDEX application_onboarding_entitlement_event_entitlement_idx
    ON mtmf.application_onboarding_entitlement_event (entitlement_id, occurred_at, id);

ALTER TABLE mtmf.application_onboarding_entitlement OWNER TO mtmf_owner;
ALTER TABLE mtmf.application_onboarding_entitlement_event OWNER TO mtmf_owner;
REVOKE ALL ON TABLE mtmf.application_onboarding_entitlement FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.application_onboarding_entitlement_event FROM PUBLIC;
