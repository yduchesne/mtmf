-- v013: privilege posture for the privileged partition-maintenance helper.
--
-- The helper is owner-owned, SECURITY INVOKER, fixed empty search_path, and
-- is never executable by PUBLIC or the restricted runtime. Partition DDL is
-- an operator action performed after explicitly assuming the owner role. The
-- existing 78-function runtime allowlist is unchanged.

ALTER FUNCTION mtmf.ensure_security_mutation_audit_month(date) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.ensure_security_mutation_audit_month(date) SECURITY INVOKER;
ALTER FUNCTION mtmf.ensure_security_mutation_audit_month(date) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.ensure_security_mutation_audit_month(date) FROM PUBLIC;
REVOKE ALL ON FUNCTION mtmf.ensure_security_mutation_audit_month(date) FROM mtmf_runtime;
