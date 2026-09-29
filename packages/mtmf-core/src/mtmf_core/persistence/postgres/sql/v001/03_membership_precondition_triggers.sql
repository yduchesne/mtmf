-- Typed membership precondition triggers.
--
-- Every typed membership table validates its structural prerequisites
-- immediately at INSERT time (BEFORE INSERT). Updates to membership rows
-- are blocked entirely by the immutability guard (04), so insert-time
-- validation is sufficient for the invariants to hold over time.
--
-- Trigger functions and triggers are schema-qualified and never depend
-- on search_path. No SQLSTATE, authorization, or user context is used.

CREATE OR REPLACE FUNCTION mtmf.identity_tenant_membership_check()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    PERFORM mtmf.identity_tenant_membership_precondition(NEW.identity_id, NEW.tenant_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_tenant_membership_precondition_trigger
    BEFORE INSERT ON mtmf.identity_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.identity_tenant_membership_check();

CREATE OR REPLACE FUNCTION mtmf.group_tenant_membership_check()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    PERFORM mtmf.group_tenant_membership_precondition(NEW.group_id, NEW.tenant_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER group_tenant_membership_precondition_trigger
    BEFORE INSERT ON mtmf.group_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.group_tenant_membership_check();

CREATE OR REPLACE FUNCTION mtmf.identity_group_membership_check()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    PERFORM mtmf.identity_group_membership_precondition(NEW.identity_id, NEW.group_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_group_membership_precondition_trigger
    BEFORE INSERT ON mtmf.identity_group_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.identity_group_membership_check();

CREATE OR REPLACE FUNCTION mtmf.identity_org_membership_check()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    PERFORM mtmf.identity_org_membership_precondition(NEW.identity_id, NEW.organization_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_org_membership_precondition_trigger
    BEFORE INSERT ON mtmf.identity_org_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.identity_org_membership_check();

CREATE OR REPLACE FUNCTION mtmf.group_org_membership_check()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    PERFORM mtmf.group_org_membership_precondition(NEW.group_id, NEW.organization_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER group_org_membership_precondition_trigger
    BEFORE INSERT ON mtmf.group_org_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.group_org_membership_check();