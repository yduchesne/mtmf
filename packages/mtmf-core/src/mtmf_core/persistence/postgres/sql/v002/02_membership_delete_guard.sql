-- Typed membership DELETE guard (v002).
--
-- Memberships are hard-deleted only through the sanctioned removal
-- functions (03), which set the transaction-local
-- ``mtmf.membership_removal`` marker for the duration of their own deletes.
-- A direct ``DELETE`` from any typed membership table therefore fails
-- loudly instead of silently bypassing the cascade and the compact audit.
--
-- The guard is a row-level BEFORE DELETE trigger, so it fires for direct
-- SQL and for the removal functions alike; table owners cannot skip it.
-- It is a trusted-persistence-boundary control, not an authorization
-- boundary: a role that can issue arbitrary SQL could set the marker
-- itself (see docs/ARCHITECTURE.md for the documented limitation), but the
-- ordinary application/connector path cannot remove a membership without
-- the exactly-once audit row.

CREATE OR REPLACE FUNCTION mtmf.membership_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF current_setting('mtmf.membership_removal', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION
          'typed membership rows may only be removed through the MTMF removal functions';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER principal_tenant_membership_delete_guard
    BEFORE DELETE ON mtmf.principal_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER identity_tenant_membership_delete_guard
    BEFORE DELETE ON mtmf.identity_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER group_tenant_membership_delete_guard
    BEFORE DELETE ON mtmf.group_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER identity_group_membership_delete_guard
    BEFORE DELETE ON mtmf.identity_group_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER identity_org_membership_delete_guard
    BEFORE DELETE ON mtmf.identity_org_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER group_org_membership_delete_guard
    BEFORE DELETE ON mtmf.group_org_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.membership_delete_guard();

-- TRUNCATE bypasses row-level DELETE triggers; a statement-level guard
-- closes that path so bulk removal cannot skip the cascade/audit boundary.
CREATE TRIGGER principal_tenant_membership_truncate_guard
    BEFORE TRUNCATE ON mtmf.principal_tenant_membership
    FOR EACH STATEMENT EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER identity_tenant_membership_truncate_guard
    BEFORE TRUNCATE ON mtmf.identity_tenant_membership
    FOR EACH STATEMENT EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER group_tenant_membership_truncate_guard
    BEFORE TRUNCATE ON mtmf.group_tenant_membership
    FOR EACH STATEMENT EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER identity_group_membership_truncate_guard
    BEFORE TRUNCATE ON mtmf.identity_group_membership
    FOR EACH STATEMENT EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER identity_org_membership_truncate_guard
    BEFORE TRUNCATE ON mtmf.identity_org_membership
    FOR EACH STATEMENT EXECUTE FUNCTION mtmf.membership_delete_guard();

CREATE TRIGGER group_org_membership_truncate_guard
    BEFORE TRUNCATE ON mtmf.group_org_membership
    FOR EACH STATEMENT EXECUTE FUNCTION mtmf.membership_delete_guard();
