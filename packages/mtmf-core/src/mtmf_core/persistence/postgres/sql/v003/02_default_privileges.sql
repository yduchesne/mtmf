-- v003: default privileges for future owner-created objects.
--
-- PostgreSQL grants PUBLIC EXECUTE on functions by default. A schema-scoped
-- ALTER DEFAULT PRIVILEGES cannot negate that built-in global default, so
-- the global form is required in addition to the schema-scoped one. All
-- MTMF DDL runs under SET ROLE mtmf_owner, so owner-scoped defaults cover
-- every future MTMF object; future grant changes must be explicit
-- migrations, never an implicit PUBLIC default.

ALTER DEFAULT PRIVILEGES FOR ROLE mtmf_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE mtmf_owner IN SCHEMA mtmf
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE mtmf_owner IN SCHEMA mtmf
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE mtmf_owner IN SCHEMA mtmf
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
