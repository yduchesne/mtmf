-- Append-only membership-removal audit guards (v002).
--
-- The audit table is a trusted persistence record: rows are inserted by the
-- sanctioned removal functions and are never updated or deleted by the
-- application boundary. These row-level guards make that explicit at the
-- database, independently of repository code.

CREATE OR REPLACE FUNCTION mtmf.guard_membership_removal_audit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    RAISE EXCEPTION
      'membership_removal_audit rows are append-only and cannot be updated or deleted';
END;
$$;

CREATE TRIGGER membership_removal_audit_update_guard
    BEFORE UPDATE ON mtmf.membership_removal_audit
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_membership_removal_audit();

CREATE TRIGGER membership_removal_audit_delete_guard
    BEFORE DELETE ON mtmf.membership_removal_audit
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_membership_removal_audit();

CREATE TRIGGER membership_removal_audit_truncate_guard
    BEFORE TRUNCATE ON mtmf.membership_removal_audit
    FOR EACH STATEMENT EXECUTE FUNCTION mtmf.guard_membership_removal_audit();
