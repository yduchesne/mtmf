-- Structural immutability guards.
--
-- Domain identity/provenance fields (UUID ids, Role/Action URNs,
-- structural Tenant/Principal references, PermissionSet effect, and all
-- typed membership facts) are immutable. These BEFORE UPDATE triggers
-- make that boundary authoritative at the database: mutable columns
-- (names, descriptions, extension objects, deletion status, ordering
-- positions) remain updatable; identity/structural columns never are.
--
-- Typed membership facts are frozen value objects in the domain, so any
-- UPDATE on a membership row is rejected (state changes are expressed by
-- deleting and re-inserting the fact, which future write layers own).
-- Hard DELETEs of referenced entity rows stay blocked by the restrictive
-- (NO ACTION) foreign keys, matching soft-deletion semantics.
--
-- No dynamic SQL is used; every comparison is explicit and reviewable.

CREATE OR REPLACE FUNCTION mtmf.guard_tenant_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.owner_identity_id IS DISTINCT FROM OLD.owner_identity_id THEN
        RAISE EXCEPTION 'tenant: immutable identity/provenance columns cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenant_immutable_columns_guard
    BEFORE UPDATE ON mtmf.tenant
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_tenant_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.guard_organization_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.owner_identity_id IS DISTINCT FROM OLD.owner_identity_id THEN
        RAISE EXCEPTION 'organization: immutable identity/structural/provenance columns cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organization_immutable_columns_guard
    BEFORE UPDATE ON mtmf.organization
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_organization_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.guard_principal_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'principal: immutable identity column cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER principal_immutable_columns_guard
    BEFORE UPDATE ON mtmf.principal
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_principal_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.guard_identity_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id THEN
        RAISE EXCEPTION 'identity: immutable identity/structural columns cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_immutable_columns_guard
    BEFORE UPDATE ON mtmf.identity
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_identity_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.guard_group_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'group: immutable identity/structural columns cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER group_immutable_columns_guard
    BEFORE UPDATE ON mtmf.group
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_group_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.guard_role_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.urn IS DISTINCT FROM OLD.urn
       OR NEW.defining_tenant_id IS DISTINCT FROM OLD.defining_tenant_id THEN
        RAISE EXCEPTION 'role: immutable URN/definition-ownership columns cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER role_immutable_columns_guard
    BEFORE UPDATE ON mtmf.role
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_role_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.guard_permission_set_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.role_urn IS DISTINCT FROM OLD.role_urn
       OR NEW.effect IS DISTINCT FROM OLD.effect THEN
        RAISE EXCEPTION 'permission_set: immutable identity/ownership/effect columns cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER permission_set_immutable_columns_guard
    BEFORE UPDATE ON mtmf.permission_set
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_permission_set_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.guard_permission_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.permission_set_id IS DISTINCT FROM OLD.permission_set_id
       OR NEW.urn IS DISTINCT FROM OLD.urn THEN
        RAISE EXCEPTION 'permission: immutable identity/ownership/matcher columns cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER permission_immutable_columns_guard
    BEFORE UPDATE ON mtmf.permission
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_permission_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.guard_action_immutable_columns()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.urn IS DISTINCT FROM OLD.urn THEN
        RAISE EXCEPTION 'action: the exact Action URN is immutable and cannot be updated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER action_immutable_columns_guard
    BEFORE UPDATE ON mtmf.action
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_action_immutable_columns();

CREATE OR REPLACE FUNCTION mtmf.block_membership_updates()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    RAISE EXCEPTION
      'typed membership facts are immutable; delete and re-insert the relationship instead';
END;
$$;

CREATE TRIGGER principal_tenant_membership_update_block
    BEFORE UPDATE ON mtmf.principal_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.block_membership_updates();

CREATE TRIGGER identity_tenant_membership_update_block
    BEFORE UPDATE ON mtmf.identity_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.block_membership_updates();

CREATE TRIGGER group_tenant_membership_update_block
    BEFORE UPDATE ON mtmf.group_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.block_membership_updates();

CREATE TRIGGER identity_group_membership_update_block
    BEFORE UPDATE ON mtmf.identity_group_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.block_membership_updates();

CREATE TRIGGER identity_org_membership_update_block
    BEFORE UPDATE ON mtmf.identity_org_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.block_membership_updates();

CREATE TRIGGER group_org_membership_update_block
    BEFORE UPDATE ON mtmf.group_org_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.block_membership_updates();