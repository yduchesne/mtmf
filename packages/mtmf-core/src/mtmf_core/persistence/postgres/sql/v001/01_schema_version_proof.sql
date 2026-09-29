-- MTMF schema-version proof function.
--
-- Installed by Alembic from the packaged versioned SQL resource v001.
-- This is infrastructure that proves packaged, schema-qualified SQL
-- functions install from an empty database; it is not repository CRUD.
-- The function is IMMUTABLE and does not depend on search_path.

CREATE OR REPLACE FUNCTION mtmf.mtf_schema_version()
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = ''
AS $$
    SELECT 'mtmf-schema-v001';
$$;