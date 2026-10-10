-- v007: explicit Identity origin and Tenant lifecycle (PR 10).
--
-- ``identity.origin`` is an immutable LOCAL(=1)/FEDERATED(=2) classification.
-- ``tenant.lifecycle`` is an explicit PROVISIONING(=0)/ACTIVE(=1)/
-- SUSPENDED(=2) state, independent of soft deletion; the root Tenant must be
-- ACTIVE.
--
-- v0.1 targets a fresh database, but populated dev/upgrade databases still
-- exist. The columns are therefore added with the *conservative* value for
-- any pre-existing row and the default is then dropped so new inserts must
-- state the value explicitly:
--   * existing Identities become FEDERATED (never silently LOCAL, so they
--     cannot be treated as the mandatory local/root acting Identity);
--   * existing ordinary Tenants become PROVISIONING (non-authorizing).
-- A root Tenant can never be created by this path with a non-ACTIVE state.

ALTER TABLE mtmf.tenant
    ADD COLUMN lifecycle smallint NOT NULL DEFAULT 0;

ALTER TABLE mtmf.tenant
    ALTER COLUMN lifecycle DROP DEFAULT;

ALTER TABLE mtmf.tenant
    ADD CONSTRAINT tenant_lifecycle_check CHECK (lifecycle IN (0, 1, 2));

-- The unique root Tenant is always ACTIVE and cannot be suspended/demoted.
ALTER TABLE mtmf.tenant
    ADD CONSTRAINT tenant_root_lifecycle_check CHECK (scope <> 0 OR lifecycle = 1);

ALTER TABLE mtmf.identity
    ADD COLUMN origin smallint NOT NULL DEFAULT 2;

ALTER TABLE mtmf.identity
    ALTER COLUMN origin DROP DEFAULT;

ALTER TABLE mtmf.identity
    ADD CONSTRAINT identity_origin_check CHECK (origin IN (1, 2));

-- The Identity origin is immutable: extend the existing guard so a direct
-- UPDATE or a save function can never reclassify an Identity.
CREATE OR REPLACE FUNCTION mtmf.guard_identity_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.origin IS DISTINCT FROM OLD.origin THEN
        RAISE EXCEPTION 'identity: immutable identity/structural/origin columns cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;
