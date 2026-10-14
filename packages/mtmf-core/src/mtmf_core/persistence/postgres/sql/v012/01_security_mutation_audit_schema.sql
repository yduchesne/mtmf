-- v012: append-only security-state mutation audit table (PR 19C).
--
-- One durable row per actually-applied verified security-state mutation.
-- PR 19B alone owns date partitioning; this revision creates the table
-- unpartitioned. Rows are append-only: UPDATE/DELETE/TRUNCATE are rejected
-- by row/statement guards, and no non-owner role holds table DML.
--
-- ``id`` is the server-generated per-attempt ``operation_id`` (not a client
-- idempotency key). ``(tenant_id, identity_id, group_id)`` is the logical
-- membership identity; ``occurred_at`` records the commit-attempt time.
-- The row deliberately carries no foreign keys so that soft/hard entity
-- changes can never obstruct or cascade immutable audit history.

CREATE TABLE mtmf.security_mutation_audit (
    id uuid NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    authorized_at timestamptz NOT NULL,
    actor_identity_id uuid NOT NULL,
    actor_principal_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    application_id uuid NOT NULL,
    action_urn text NOT NULL,
    target_kind text NOT NULL,
    target_id uuid NOT NULL,
    subject_identity_id uuid NOT NULL,
    outcome text NOT NULL,
    CONSTRAINT security_mutation_audit_pk PRIMARY KEY (id),
    CONSTRAINT security_mutation_audit_outcome_check CHECK (outcome = 'CREATED'),
    CONSTRAINT security_mutation_audit_target_kind_check
        CHECK (target_kind = 'identity_group_membership'),
    CONSTRAINT security_mutation_audit_action_urn_check
        CHECK (action_urn = 'urn:mtmf:iam:actions:system:identity-group-membership:add-object')
);

CREATE INDEX security_mutation_audit_tenant_occurred_idx
    ON mtmf.security_mutation_audit (tenant_id, occurred_at DESC);

CREATE INDEX security_mutation_audit_target_occurred_idx
    ON mtmf.security_mutation_audit (target_kind, target_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION mtmf.guard_security_mutation_audit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'MT033',
        MESSAGE = 'security_mutation_audit rows are append-only';
END;
$$;

CREATE TRIGGER security_mutation_audit_update_guard
    BEFORE UPDATE ON mtmf.security_mutation_audit
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_security_mutation_audit();

CREATE TRIGGER security_mutation_audit_delete_guard
    BEFORE DELETE ON mtmf.security_mutation_audit
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_security_mutation_audit();

CREATE TRIGGER security_mutation_audit_truncate_guard
    BEFORE TRUNCATE ON mtmf.security_mutation_audit
    FOR EACH STATEMENT EXECUTE FUNCTION mtmf.guard_security_mutation_audit();

ALTER TABLE mtmf.security_mutation_audit OWNER TO mtmf_owner;
REVOKE ALL ON TABLE mtmf.security_mutation_audit FROM PUBLIC;
