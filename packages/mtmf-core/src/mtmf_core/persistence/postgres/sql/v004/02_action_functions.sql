-- v004: Action repository functions.
--
-- An Action is a shared exact definition identified solely by its
-- immutable Action URN; it has no mutable state, so only add/get exist.

CREATE OR REPLACE FUNCTION mtmf.action_add(urn_value text)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH inserted AS (
        INSERT INTO mtmf.action (urn)
        VALUES (urn_value)
        ON CONFLICT (urn) DO NOTHING
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM inserted);
$$;

CREATE OR REPLACE FUNCTION mtmf.action_get(urn_value text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (SELECT 1 FROM mtmf.action WHERE urn = urn_value);
$$;
