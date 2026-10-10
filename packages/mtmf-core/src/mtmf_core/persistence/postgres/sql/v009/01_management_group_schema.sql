-- v009: TenantManagementGroup structural schema (PR 11).
--
-- ``tenant_management_group`` records one manager Tenant, one approved
-- SYSTEM management Role, and a ROOT/SYSTEM management scope.
-- ``tenant_management_group_membership`` records explicit SYSTEM managed
-- Tenants. ``tenant_management_group_actor_eligibility`` records the
-- explicit Identity-level eligibility designations required by Gate D D01.
--
-- These tables are owner-owned and have no runtime DML privilege: all
-- mutation is installation/operator-only. The ROOT management Role and
-- management Permission are installed by the v009 seed.

CREATE TABLE mtmf.tenant_management_group (
    id uuid NOT NULL,
    manager_tenant_id uuid NOT NULL,
    management_role_urn text NOT NULL,
    scope smallint NOT NULL,
    CONSTRAINT tenant_management_group_pk PRIMARY KEY (id),
    CONSTRAINT tenant_management_group_scope_check CHECK (scope IN (0, 1)),
    CONSTRAINT tenant_management_group_manager_fk FOREIGN KEY (manager_tenant_id)
        REFERENCES mtmf.tenant (id),
    CONSTRAINT tenant_management_group_role_fk FOREIGN KEY (management_role_urn)
        REFERENCES mtmf.role (urn),
    CONSTRAINT tenant_management_group_scope_role_check CHECK (
        (
            scope = 0
            AND management_role_urn = 'urn:mtmf:iam:roles:system:root-tenant-management'
        )
        OR (
            scope = 1
            AND management_role_urn = 'urn:mtmf:iam:roles:system:tenant-management'
        )
    )
);

-- A single ROOT management group: uniqueness is enforced by the database,
-- independent of application logic. SYSTEM groups are unbounded.
CREATE UNIQUE INDEX tenant_management_group_root_singleton
    ON mtmf.tenant_management_group (scope)
    WHERE scope = 0;

CREATE TABLE mtmf.tenant_management_group_membership (
    id uuid NOT NULL,
    management_group_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    CONSTRAINT tenant_management_group_membership_pk PRIMARY KEY (id),
    CONSTRAINT tenant_management_group_membership_group_fk
        FOREIGN KEY (management_group_id)
        REFERENCES mtmf.tenant_management_group (id),
    CONSTRAINT tenant_management_group_membership_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES mtmf.tenant (id),
    CONSTRAINT tenant_management_group_membership_unique
        UNIQUE (management_group_id, tenant_id)
);

CREATE TABLE mtmf.tenant_management_group_actor_eligibility (
    id uuid NOT NULL,
    management_group_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    CONSTRAINT tenant_management_group_actor_eligibility_pk PRIMARY KEY (id),
    CONSTRAINT tenant_management_group_actor_eligibility_group_fk
        FOREIGN KEY (management_group_id)
        REFERENCES mtmf.tenant_management_group (id),
    CONSTRAINT tenant_management_group_actor_eligibility_identity_fk
        FOREIGN KEY (identity_id) REFERENCES mtmf.identity (id),
    CONSTRAINT tenant_management_group_actor_eligibility_unique
        UNIQUE (management_group_id, identity_id)
);

ALTER TABLE mtmf.tenant_management_group OWNER TO mtmf_owner;
ALTER TABLE mtmf.tenant_management_group_membership OWNER TO mtmf_owner;
ALTER TABLE mtmf.tenant_management_group_actor_eligibility OWNER TO mtmf_owner;
REVOKE ALL ON TABLE mtmf.tenant_management_group FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.tenant_management_group_membership FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.tenant_management_group_actor_eligibility FROM PUBLIC;
