-- v008: canonical root registry, stewardship designation, and audit (PR 10).
--
-- ``root_registry`` is a protected singleton recording the immutable
-- canonical root Tenant/Principal and the designated LOCAL root acting
-- Identity. ``stewardship_designation`` records, per ordinary Tenant, the
-- single eligible steward Principal and its explicitly designated acting
-- Identity. ``stewardship_audit`` is append-only.
--
-- These tables are owner-owned and have no runtime DML privilege.

-- Required for the composite root/steward identity-ownership foreign keys.
ALTER TABLE mtmf.identity
    ADD CONSTRAINT identity_id_principal_unique UNIQUE (id, principal_id);

CREATE TABLE mtmf.root_registry (
    singleton boolean NOT NULL DEFAULT true,
    root_tenant_id uuid NOT NULL,
    root_principal_id uuid NOT NULL,
    root_identity_id uuid NOT NULL,
    bootstrap_version integer NOT NULL,
    CONSTRAINT root_registry_pk PRIMARY KEY (singleton),
    CONSTRAINT root_registry_singleton_check CHECK (singleton),
    CONSTRAINT root_registry_version_check CHECK (bootstrap_version >= 1),
    CONSTRAINT root_registry_tenant_fk FOREIGN KEY (root_tenant_id)
        REFERENCES mtmf.tenant (id),
    CONSTRAINT root_registry_principal_fk FOREIGN KEY (root_principal_id)
        REFERENCES mtmf.principal (id),
    CONSTRAINT root_registry_identity_principal_fk
        FOREIGN KEY (root_identity_id, root_principal_id)
        REFERENCES mtmf.identity (id, principal_id)
);

CREATE TABLE mtmf.stewardship_designation (
    tenant_id uuid NOT NULL,
    steward_principal_id uuid NOT NULL,
    designated_identity_id uuid NOT NULL,
    version integer NOT NULL,
    CONSTRAINT stewardship_designation_pk PRIMARY KEY (tenant_id),
    CONSTRAINT stewardship_designation_version_check CHECK (version >= 1),
    CONSTRAINT stewardship_designation_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES mtmf.tenant (id),
    CONSTRAINT stewardship_designation_principal_fk FOREIGN KEY (steward_principal_id)
        REFERENCES mtmf.principal (id),
    CONSTRAINT stewardship_designation_identity_principal_fk
        FOREIGN KEY (designated_identity_id, steward_principal_id)
        REFERENCES mtmf.identity (id, principal_id)
);

CREATE TABLE mtmf.stewardship_audit (
    id bigint GENERATED ALWAYS AS IDENTITY,
    tenant_id uuid NOT NULL,
    operation text NOT NULL,
    previous_principal_id uuid,
    new_principal_id uuid NOT NULL,
    previous_identity_id uuid,
    new_identity_id uuid NOT NULL,
    actor_provenance text,
    reason text,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT stewardship_audit_pk PRIMARY KEY (id),
    CONSTRAINT stewardship_audit_operation_check
        CHECK (operation IN ('BOOTSTRAP', 'TRANSFER', 'RECOVERY', 'ROOT_IDENTITY_RECOVERY'))
);

ALTER TABLE mtmf.root_registry OWNER TO mtmf_owner;
ALTER TABLE mtmf.stewardship_designation OWNER TO mtmf_owner;
ALTER TABLE mtmf.stewardship_audit OWNER TO mtmf_owner;
REVOKE ALL ON TABLE mtmf.root_registry FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.stewardship_designation FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.stewardship_audit FROM PUBLIC;
