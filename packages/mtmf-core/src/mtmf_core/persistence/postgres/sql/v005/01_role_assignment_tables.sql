-- v005: typed, Tenant-bound Role-assignment tables.
--
-- Two explicit assignment entities are introduced; there is deliberately
-- no polymorphic ``subject_type``/``subject_id`` relationship. Every
-- assignment has an immutable surrogate UUID identity plus an immutable
-- logical tuple ``(tenant, subject, role, organization)``. A NULL
-- ``organization_id`` denotes a Tenant-wide assignment and participates in
-- logical uniqueness as a real value (``NULLS NOT DISTINCT``), so a
-- Tenant-wide duplicate is a deterministic conflict.
--
-- Structural safety is enforced with composite foreign keys, not merely in
-- application code:
--
--   * ``(identity_id, tenant_id)`` references the Identity-Tenant
--     membership row, so a direct assignment requires an explicit,
--     same-Tenant IdentityTenantMembership. The same holds for Groups via
--     ``(group_id, tenant_id)`` and GroupTenantMembership.
--   * ``(organization_id, tenant_id)`` references ``organization(id,
--     tenant_id)``, so an Organization refinement can only name an
--     Organization inside the assignment Tenant.
--   * a plain ``role_urn`` foreign key requires the Role to exist; the
--     trusted stored function additionally rejects a TENANT-defined Role
--     assigned outside its defining Tenant.
--
-- The composite membership foreign keys are the deliberate prerequisite
-- deletion policy: an assignment is **restricted** while its prerequisite
-- membership exists. Removing a prerequisite membership while a dependent
-- assignment remains is rejected deterministically by the database and
-- rolls the whole removal (and any membership cascade/audit) back; a
-- caller must revoke the assignment explicitly first. Assignments are
-- never silently cascade-deleted by membership removal.
--
-- No table or sequence privilege is granted to ``mtmf_runtime``; every
-- runtime read/write goes through a reviewed SECURITY DEFINER function in
-- ``02`` and its exact grant in ``03``.

CREATE TABLE mtmf.identity_role_assignment (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    role_urn text NOT NULL,
    organization_id uuid NULL,
    CONSTRAINT identity_role_assignment_pk PRIMARY KEY (id),
    CONSTRAINT identity_role_assignment_logical_unique
        UNIQUE NULLS NOT DISTINCT (tenant_id, identity_id, role_urn, organization_id)
);

CREATE TABLE mtmf.group_role_assignment (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    role_urn text NOT NULL,
    organization_id uuid NULL,
    CONSTRAINT group_role_assignment_pk PRIMARY KEY (id),
    CONSTRAINT group_role_assignment_logical_unique
        UNIQUE NULLS NOT DISTINCT (tenant_id, group_id, role_urn, organization_id)
);

-- The composite Organization target for the assignment Organization
-- foreign keys. ``id`` is already the primary key; this wider unique key
-- exists solely so ``(organization_id, tenant_id)`` can be referenced and
-- proves the Organization belongs to the assignment Tenant.
ALTER TABLE mtmf.organization
    ADD CONSTRAINT organization_id_tenant_unique UNIQUE (id, tenant_id);

ALTER TABLE mtmf.identity_role_assignment
    ADD CONSTRAINT identity_role_assignment_identity_tenant_fk
    FOREIGN KEY (identity_id, tenant_id)
    REFERENCES mtmf.identity_tenant_membership (identity_id, tenant_id);

ALTER TABLE mtmf.identity_role_assignment
    ADD CONSTRAINT identity_role_assignment_organization_fk
    FOREIGN KEY (organization_id, tenant_id)
    REFERENCES mtmf.organization (id, tenant_id);

ALTER TABLE mtmf.identity_role_assignment
    ADD CONSTRAINT identity_role_assignment_role_fk
    FOREIGN KEY (role_urn) REFERENCES mtmf.role (urn);

ALTER TABLE mtmf.group_role_assignment
    ADD CONSTRAINT group_role_assignment_group_tenant_fk
    FOREIGN KEY (group_id, tenant_id)
    REFERENCES mtmf.group_tenant_membership (group_id, tenant_id);

ALTER TABLE mtmf.group_role_assignment
    ADD CONSTRAINT group_role_assignment_organization_fk
    FOREIGN KEY (organization_id, tenant_id)
    REFERENCES mtmf.organization (id, tenant_id);

ALTER TABLE mtmf.group_role_assignment
    ADD CONSTRAINT group_role_assignment_role_fk
    FOREIGN KEY (role_urn) REFERENCES mtmf.role (urn);

CREATE INDEX identity_role_assignment_tenant_identity_idx
    ON mtmf.identity_role_assignment (tenant_id, identity_id);
CREATE INDEX identity_role_assignment_tenant_organization_idx
    ON mtmf.identity_role_assignment (tenant_id, organization_id);
CREATE INDEX identity_role_assignment_role_urn_idx
    ON mtmf.identity_role_assignment (role_urn);

CREATE INDEX group_role_assignment_tenant_group_idx
    ON mtmf.group_role_assignment (tenant_id, group_id);
CREATE INDEX group_role_assignment_tenant_organization_idx
    ON mtmf.group_role_assignment (tenant_id, organization_id);
CREATE INDEX group_role_assignment_role_urn_idx
    ON mtmf.group_role_assignment (role_urn);
