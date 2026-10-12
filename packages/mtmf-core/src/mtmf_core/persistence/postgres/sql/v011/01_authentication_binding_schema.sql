-- v011: authentication binding schema (PR 14 development scope).
--
-- Two immutable binding facts used by verified D1 actor composition:
--
--   * ``service_credential_application`` — an immutable ``(issuer, client_id)``
--     credential mapped to exactly one registered Application;
--   * ``external_subject_identity``       — an immutable ``(issuer, subject)``
--     mapped to exactly one MTMF Identity.
--
-- Semantic keys and targets are immutable; only the lifecycle may change, and
-- only ACTIVE -> REVOKED (terminal). At most one ACTIVE row exists per
-- semantic key. No runtime table privilege is granted.

CREATE TABLE mtmf.service_credential_application (
    id uuid NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    application_id uuid NOT NULL,
    lifecycle smallint NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT service_credential_application_pk PRIMARY KEY (id),
    CONSTRAINT service_credential_application_lifecycle_check CHECK (lifecycle IN (1, 2)),
    CONSTRAINT service_credential_application_issuer_check CHECK (length(issuer) BETWEEN 1 AND 512),
    CONSTRAINT service_credential_application_client_check CHECK (length(client_id) BETWEEN 1 AND 255),
    CONSTRAINT service_credential_application_application_fk
        FOREIGN KEY (application_id) REFERENCES mtmf.application (id)
);

CREATE UNIQUE INDEX service_credential_application_current_unique
    ON mtmf.service_credential_application (issuer, client_id)
    WHERE lifecycle = 1;

CREATE TABLE mtmf.external_subject_identity (
    id uuid NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    identity_id uuid NOT NULL,
    lifecycle smallint NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT external_subject_identity_pk PRIMARY KEY (id),
    CONSTRAINT external_subject_identity_lifecycle_check CHECK (lifecycle IN (1, 2)),
    CONSTRAINT external_subject_identity_issuer_check CHECK (length(issuer) BETWEEN 1 AND 512),
    CONSTRAINT external_subject_identity_subject_check CHECK (length(subject) BETWEEN 1 AND 512),
    CONSTRAINT external_subject_identity_identity_fk
        FOREIGN KEY (identity_id) REFERENCES mtmf.identity (id)
);

CREATE UNIQUE INDEX external_subject_identity_current_unique
    ON mtmf.external_subject_identity (issuer, subject)
    WHERE lifecycle = 1;

ALTER TABLE mtmf.service_credential_application OWNER TO mtmf_owner;
ALTER TABLE mtmf.external_subject_identity OWNER TO mtmf_owner;
REVOKE ALL ON TABLE mtmf.service_credential_application FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.external_subject_identity FROM PUBLIC;
