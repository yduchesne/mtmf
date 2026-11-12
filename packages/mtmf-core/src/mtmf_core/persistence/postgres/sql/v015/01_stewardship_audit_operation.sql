-- v015: extend the stewardship audit operation taxonomy (PR 23).
--
-- The PR 10 append-only ``stewardship_audit`` accepted four installation/
-- operator operations. PR 23 adds exactly one initial-onboarding value so the
-- owner-only transaction participant can record the structural first-steward
-- graph without mislabelling it as TRANSFER or RECOVERY.
--
-- This is an additive constraint replacement inside the migration
-- transaction. Every historical value is preserved, no row is deleted, and the
-- append-only triggers are untouched. The constraint name is the reviewed
-- v008 ``stewardship_audit_operation_check``.

ALTER TABLE mtmf.stewardship_audit
    DROP CONSTRAINT stewardship_audit_operation_check;

ALTER TABLE mtmf.stewardship_audit
    ADD CONSTRAINT stewardship_audit_operation_check
    CHECK (
        operation IN (
            'BOOTSTRAP',
            'TRANSFER',
            'RECOVERY',
            'ROOT_IDENTITY_RECOVERY',
            'INITIAL_ONBOARDING'
        )
    );
