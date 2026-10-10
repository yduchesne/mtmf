-- v006: protected built-in SYSTEM policy registry (PR 10, approved Gate M seed).
--
-- ``builtin_role`` records exactly which SYSTEM-owned Role definitions were
-- installed by the reviewed PR #38 seed. It exists so the database -- not a
-- documentation statement -- can prevent ordinary runtime Role mutation
-- (``role_save``) from rewriting the approved built-in policy. Controlled
-- owner/migrator migrations evolve these definitions directly and never
-- depend on the runtime entry point.
--
-- The registry references the authoritative Role row by URN with a
-- restrictive foreign key, so a protected marker can never outlive its Role.

CREATE TABLE mtmf.builtin_role (
    role_urn text NOT NULL,
    CONSTRAINT builtin_role_pk PRIMARY KEY (role_urn),
    CONSTRAINT builtin_role_role_fk FOREIGN KEY (role_urn) REFERENCES mtmf.role (urn)
);

ALTER TABLE mtmf.builtin_role OWNER TO mtmf_owner;
REVOKE ALL ON TABLE mtmf.builtin_role FROM PUBLIC;
