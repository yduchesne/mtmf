-- v010: Application registry and Tenant subscription schema (PR 13).
--
-- Three independent aggregates (decision S1):
--
--   * ``application``                        — a global registered Application;
--   * ``application_tenant_registration``    — the explicit fact that the
--     Application is permitted to operate for one Tenant;
--   * ``tenant_application_subscription``    — the time-bounded fact that a
--     Tenant subscribes to an Application.
--
-- Registration and subscription are separate security facts: neither
-- implies the other, and neither is authorization. Only the partial unique
-- indexes below enforce at most one *current* row per
-- ``(application_id, tenant_id)`` pair; terminal rows (REVOKED,
-- CANCELLED, EXPIRED) remain as history and never block a later current
-- row.
--
-- No table or sequence privilege is granted to ``mtmf_runtime``: every
-- runtime read goes through a reviewed SECURITY DEFINER function in
-- ``02``/``03``, and every mutation is operator/installation-only.

CREATE TABLE mtmf.application (
    id uuid NOT NULL,
    application_key text NOT NULL,
    name text NOT NULL,
    owner_identity_id uuid NOT NULL,
    lifecycle smallint NOT NULL,
    extension jsonb NOT NULL,
    CONSTRAINT application_pk PRIMARY KEY (id),
    CONSTRAINT application_key_unique UNIQUE (application_key),
    CONSTRAINT application_key_check CHECK (
        application_key ~ '^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$'
    ),
    CONSTRAINT application_lifecycle_check CHECK (lifecycle IN (1, 2, 3)),
    CONSTRAINT application_extension_object CHECK (jsonb_typeof(extension) = 'object'),
    CONSTRAINT application_owner_fk FOREIGN KEY (owner_identity_id)
        REFERENCES mtmf.identity (id)
);

CREATE TABLE mtmf.application_tenant_registration (
    id uuid NOT NULL,
    application_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    created_by_identity_id uuid NOT NULL,
    lifecycle smallint NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT application_tenant_registration_pk PRIMARY KEY (id),
    CONSTRAINT application_tenant_registration_lifecycle_check
        CHECK (lifecycle IN (1, 2)),
    CONSTRAINT application_tenant_registration_application_fk
        FOREIGN KEY (application_id) REFERENCES mtmf.application (id),
    CONSTRAINT application_tenant_registration_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES mtmf.tenant (id),
    CONSTRAINT application_tenant_registration_creator_fk
        FOREIGN KEY (created_by_identity_id) REFERENCES mtmf.identity (id)
);

CREATE UNIQUE INDEX application_tenant_registration_current_unique
    ON mtmf.application_tenant_registration (application_id, tenant_id)
    WHERE lifecycle = 1;

CREATE INDEX application_tenant_registration_tenant_idx
    ON mtmf.application_tenant_registration (tenant_id);

CREATE TABLE mtmf.tenant_application_subscription (
    id uuid NOT NULL,
    application_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    created_by_identity_id uuid NOT NULL,
    lifecycle smallint NOT NULL,
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT tenant_application_subscription_pk PRIMARY KEY (id),
    CONSTRAINT tenant_application_subscription_lifecycle_check
        CHECK (lifecycle IN (0, 1, 2, 3, 4)),
    CONSTRAINT tenant_application_subscription_window_check
        CHECK (ends_at IS NULL OR ends_at > starts_at),
    CONSTRAINT tenant_application_subscription_application_fk
        FOREIGN KEY (application_id) REFERENCES mtmf.application (id),
    CONSTRAINT tenant_application_subscription_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES mtmf.tenant (id),
    CONSTRAINT tenant_application_subscription_creator_fk
        FOREIGN KEY (created_by_identity_id) REFERENCES mtmf.identity (id)
);

CREATE UNIQUE INDEX tenant_application_subscription_current_unique
    ON mtmf.tenant_application_subscription (application_id, tenant_id)
    WHERE lifecycle IN (0, 1, 2);

CREATE INDEX tenant_application_subscription_tenant_idx
    ON mtmf.tenant_application_subscription (tenant_id);

ALTER TABLE mtmf.application OWNER TO mtmf_owner;
ALTER TABLE mtmf.application_tenant_registration OWNER TO mtmf_owner;
ALTER TABLE mtmf.tenant_application_subscription OWNER TO mtmf_owner;
REVOKE ALL ON TABLE mtmf.application FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.application_tenant_registration FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.tenant_application_subscription FROM PUBLIC;
