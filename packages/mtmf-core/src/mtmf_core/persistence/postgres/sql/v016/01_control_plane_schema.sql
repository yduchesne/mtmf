-- v016: PR 24P operator authority, immutable execution ledger, and audit.
--
-- This migration is role-independent: it never creates or references
-- mtmf_control_exec. All objects are owner-owned and PUBLIC-denied.

CREATE TABLE mtmf.system_operator_assignment (
    id uuid NOT NULL,
    identity_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    role_urn text NOT NULL,
    state smallint NOT NULL,
    created_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    approved_by text NOT NULL,
    approval_correlation_id uuid NOT NULL,
    source_label text NOT NULL,
    CONSTRAINT system_operator_assignment_pk PRIMARY KEY (id),
    CONSTRAINT system_operator_assignment_identity_fk FOREIGN KEY (identity_id)
        REFERENCES mtmf.identity (id),
    CONSTRAINT system_operator_assignment_principal_fk FOREIGN KEY (principal_id)
        REFERENCES mtmf.principal (id),
    CONSTRAINT system_operator_assignment_role_fk FOREIGN KEY (role_urn)
        REFERENCES mtmf.role (urn),
    CONSTRAINT system_operator_assignment_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND identity_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND principal_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND approval_correlation_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT system_operator_assignment_state_check CHECK (state IN (1, 2)),
    CONSTRAINT system_operator_assignment_role_check CHECK (
        role_urn = 'urn:mtmf:iam:roles:system:application-administrator'
    ),
    CONSTRAINT system_operator_assignment_lifecycle_check CHECK (
        (state = 1 AND revoked_at IS NULL)
        OR (state = 2 AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT system_operator_assignment_text_check CHECK (
        length(btrim(approved_by)) BETWEEN 1 AND 512
        AND length(btrim(source_label)) BETWEEN 1 AND 128
    )
);

CREATE UNIQUE INDEX system_operator_assignment_active_unique
    ON mtmf.system_operator_assignment (identity_id, role_urn)
    WHERE state = 1;

CREATE INDEX system_operator_assignment_identity_idx
    ON mtmf.system_operator_assignment (identity_id, role_urn);

CREATE TABLE mtmf.system_operator_assignment_event (
    id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    operator_identity_id uuid NOT NULL,
    operator_principal_id uuid NOT NULL,
    role_urn text NOT NULL,
    event_type smallint NOT NULL,
    occurred_at timestamptz NOT NULL,
    approved_by text NOT NULL,
    approval_correlation_id uuid NOT NULL,
    source_label text NOT NULL,
    CONSTRAINT system_operator_assignment_event_pk PRIMARY KEY (id),
    CONSTRAINT system_operator_assignment_event_assignment_fk FOREIGN KEY (assignment_id)
        REFERENCES mtmf.system_operator_assignment (id),
    CONSTRAINT system_operator_assignment_event_type_check CHECK (event_type IN (1, 2)),
    CONSTRAINT system_operator_assignment_event_role_check CHECK (
        role_urn = 'urn:mtmf:iam:roles:system:application-administrator'
    )
);

CREATE INDEX system_operator_assignment_event_assignment_idx
    ON mtmf.system_operator_assignment_event (assignment_id, occurred_at);

CREATE TABLE mtmf.system_operator_execution (
    operator_identity_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    operator_principal_id uuid NOT NULL,
    request_fingerprint bytea NOT NULL,
    operation text NOT NULL,
    action_urn text NOT NULL,
    application_id uuid NOT NULL,
    entitlement_id uuid NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    completed_at timestamptz NOT NULL,
    CONSTRAINT system_operator_execution_pk PRIMARY KEY (operator_identity_id, operation_id),
    CONSTRAINT system_operator_execution_operation_check CHECK (
        operation IN ('entitlement.grant', 'entitlement.revoke')
    ),
    CONSTRAINT system_operator_execution_outcome_check CHECK (
        outcome IN ('CREATED', 'REVOKED', 'NO_OP')
    ),
    CONSTRAINT system_operator_execution_fingerprint_check CHECK (
        octet_length(request_fingerprint) = 32
    ),
    CONSTRAINT system_operator_execution_non_nil CHECK (
        operation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND operator_identity_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND operator_principal_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND application_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND entitlement_id <> '00000000-0000-0000-0000-000000000000'::uuid
    )
);

CREATE TABLE mtmf.system_operator_execution_audit (
    id uuid NOT NULL,
    operator_identity_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    operator_principal_id uuid NOT NULL,
    action_urn text NOT NULL,
    application_id uuid NOT NULL,
    entitlement_id uuid NOT NULL,
    old_state smallint NULL,
    new_state smallint NULL,
    outcome text NOT NULL,
    executor_role text NOT NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT system_operator_execution_audit_pk PRIMARY KEY (id),
    CONSTRAINT system_operator_execution_audit_execution_fk
        FOREIGN KEY (operator_identity_id, operation_id)
        REFERENCES mtmf.system_operator_execution (operator_identity_id, operation_id),
    CONSTRAINT system_operator_execution_audit_outcome_check CHECK (
        outcome IN ('CREATED', 'REVOKED')
    ),
    CONSTRAINT system_operator_execution_audit_executor_check CHECK (
        executor_role = 'mtmf_control_exec'
    )
);

CREATE UNIQUE INDEX system_operator_execution_audit_operation_unique
    ON mtmf.system_operator_execution_audit (operator_identity_id, operation_id);

CREATE OR REPLACE FUNCTION mtmf.guard_system_operator_assignment()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'system_operator_assignment: deletion is not permitted';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.identity_id IS DISTINCT FROM OLD.identity_id
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.role_urn IS DISTINCT FROM OLD.role_urn
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.approval_correlation_id IS DISTINCT FROM OLD.approval_correlation_id
       OR NEW.source_label IS DISTINCT FROM OLD.source_label THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'system_operator_assignment: immutable provenance cannot be updated';
    END IF;
    IF OLD.state = 2 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'system_operator_assignment: REVOKED is terminal';
    END IF;
    IF NOT (OLD.state = 1 AND NEW.state = 2) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'system_operator_assignment: only ACTIVE -> REVOKED is permitted';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER system_operator_assignment_guard
    BEFORE UPDATE OR DELETE ON mtmf.system_operator_assignment
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_system_operator_assignment();

CREATE OR REPLACE FUNCTION mtmf.guard_append_only()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'MT049',
        MESSAGE = 'PR24P append-only history cannot be updated or deleted';
END;
$$;

CREATE TRIGGER system_operator_assignment_event_guard
    BEFORE UPDATE OR DELETE ON mtmf.system_operator_assignment_event
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_append_only();

CREATE TRIGGER system_operator_execution_guard
    BEFORE UPDATE OR DELETE ON mtmf.system_operator_execution
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_append_only();

CREATE TRIGGER system_operator_execution_audit_guard
    BEFORE UPDATE OR DELETE ON mtmf.system_operator_execution_audit
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_append_only();

ALTER TABLE mtmf.system_operator_assignment OWNER TO mtmf_owner;
ALTER TABLE mtmf.system_operator_assignment_event OWNER TO mtmf_owner;
ALTER TABLE mtmf.system_operator_execution OWNER TO mtmf_owner;
ALTER TABLE mtmf.system_operator_execution_audit OWNER TO mtmf_owner;
REVOKE ALL ON TABLE mtmf.system_operator_assignment FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.system_operator_assignment_event FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.system_operator_execution FROM PUBLIC;
REVOKE ALL ON TABLE mtmf.system_operator_execution_audit FROM PUBLIC;
