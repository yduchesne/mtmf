-- v008: database guards protecting canonical root and steward state across
-- every mutation path (including the pre-existing runtime-granted functions
-- that call plain UPDATE/DELETE on these tables).

-- 1. Stewardship designations must reference eligible structural state.
CREATE OR REPLACE FUNCTION mtmf.guard_stewardship_designation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NOT mtmf.stewardship_is_eligible(
        NEW.tenant_id, NEW.steward_principal_id, NEW.designated_identity_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT013',
            MESSAGE = 'stewardship designation requires an eligible Principal/acting Identity';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER stewardship_designation_guard
    BEFORE INSERT OR UPDATE ON mtmf.stewardship_designation
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_stewardship_designation();

-- 2. A root registry row must reference a ROOT-scope ACTIVE Tenant and a
--    LOCAL root Identity owned by the canonical root Principal.
CREATE OR REPLACE FUNCTION mtmf.guard_root_registry()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.tenant t
        WHERE t.id = NEW.root_tenant_id AND t.scope = 0 AND t.lifecycle = 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT030',
            MESSAGE = 'root registry requires a ROOT-scope ACTIVE root Tenant';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.identity i
        WHERE i.id = NEW.root_identity_id AND i.origin = 1
          AND i.principal_id = NEW.root_principal_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT030',
            MESSAGE = 'root registry requires a LOCAL root Identity owned by the root Principal';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER root_registry_guard
    BEFORE INSERT OR UPDATE ON mtmf.root_registry
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_root_registry();

CREATE OR REPLACE FUNCTION mtmf.guard_root_registry_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'MT030',
        MESSAGE = 'the canonical root registry cannot be deleted';
END;
$$;

CREATE TRIGGER root_registry_delete_guard
    BEFORE DELETE ON mtmf.root_registry
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_root_registry_delete();

-- 3. Canonical root Tenant/Principal/Identity protection.
CREATE OR REPLACE FUNCTION mtmf.guard_root_tenant()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    root_id uuid;
BEGIN
    SELECT root_tenant_id INTO root_id FROM mtmf.root_registry WHERE singleton;
    IF root_id IS NULL OR OLD.id IS DISTINCT FROM root_id THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT030', MESSAGE = 'the canonical root Tenant cannot be deleted';
    END IF;
    IF NEW.scope <> 0 OR NEW.lifecycle <> 1 OR NEW.deletion_status <> 2
       OR NEW.owner_identity_id IS DISTINCT FROM OLD.owner_identity_id THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT030',
            MESSAGE = 'the canonical root Tenant cannot be suspended, deleted, demoted, or reassigned';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER root_tenant_guard
    BEFORE UPDATE OR DELETE ON mtmf.tenant
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_root_tenant();

CREATE OR REPLACE FUNCTION mtmf.guard_root_principal()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    root_id uuid;
BEGIN
    SELECT root_principal_id INTO root_id FROM mtmf.root_registry WHERE singleton;
    IF root_id IS NULL OR OLD.id IS DISTINCT FROM root_id THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT030', MESSAGE = 'the canonical root Principal cannot be deleted';
    END IF;
    IF NEW.deletion_status <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT030', MESSAGE = 'the canonical root Principal cannot be soft-deleted';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER root_principal_guard
    BEFORE UPDATE OR DELETE ON mtmf.principal
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_root_principal();

CREATE OR REPLACE FUNCTION mtmf.guard_root_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    root_id uuid;
BEGIN
    SELECT root_identity_id INTO root_id FROM mtmf.root_registry WHERE singleton;
    IF root_id IS NULL OR OLD.id IS DISTINCT FROM root_id THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT030', MESSAGE = 'the designated root Identity cannot be deleted';
    END IF;
    IF NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.origin <> 1 OR NEW.deletion_status <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT030',
            MESSAGE = 'the designated root Identity cannot be reclassified, rebound, or deactivated';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER root_identity_guard
    BEFORE UPDATE OR DELETE ON mtmf.identity
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_root_identity();

-- 4. Current steward Principal/acting Identity protection.
CREATE OR REPLACE FUNCTION mtmf.guard_steward_principal()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.stewardship_designation d WHERE d.steward_principal_id = OLD.id
    ) THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT032', MESSAGE = 'the current steward Principal cannot be deleted';
    END IF;
    IF NEW.deletion_status <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT032',
            MESSAGE = 'the current steward Principal cannot be deactivated; transfer stewardship first';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER steward_principal_guard
    BEFORE UPDATE OR DELETE ON mtmf.principal
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_steward_principal();

CREATE OR REPLACE FUNCTION mtmf.guard_steward_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.stewardship_designation d WHERE d.designated_identity_id = OLD.id
    ) THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT032', MESSAGE = 'the designated steward acting Identity cannot be deleted';
    END IF;
    IF NEW.deletion_status <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT032',
            MESSAGE = 'the designated steward acting Identity cannot be deactivated; transfer or recover first';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER steward_identity_guard
    BEFORE UPDATE OR DELETE ON mtmf.identity
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_steward_identity();

-- 5. Prerequisite membership removal protection (root + current steward).
CREATE OR REPLACE FUNCTION mtmf.guard_root_steward_membership_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    registry record;
BEGIN
    SELECT * INTO registry FROM mtmf.root_registry WHERE singleton;
    IF TG_TABLE_NAME = 'principal_tenant_membership' THEN
        IF FOUND AND OLD.principal_id = registry.root_principal_id
           AND OLD.tenant_id = registry.root_tenant_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT031',
                MESSAGE = 'the canonical root Principal membership cannot be removed';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mtmf.stewardship_designation d
            WHERE d.tenant_id = OLD.tenant_id AND d.steward_principal_id = OLD.principal_id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT032',
                MESSAGE = 'the current steward Principal membership cannot be removed; transfer stewardship first';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_tenant_membership' THEN
        IF FOUND AND OLD.identity_id = registry.root_identity_id
           AND OLD.tenant_id = registry.root_tenant_id THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT031',
                MESSAGE = 'the designated root Identity membership cannot be removed';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mtmf.stewardship_designation d
            WHERE d.tenant_id = OLD.tenant_id AND d.designated_identity_id = OLD.identity_id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT032',
                MESSAGE = 'the designated steward acting Identity membership cannot be removed; transfer or recover first';
        END IF;
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER principal_tenant_membership_root_steward_guard
    BEFORE DELETE ON mtmf.principal_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_root_steward_membership_delete();

CREATE TRIGGER identity_tenant_membership_root_steward_guard
    BEFORE DELETE ON mtmf.identity_tenant_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_root_steward_membership_delete();

-- 6. An ordinary Tenant may become ACTIVE only with a designation.
CREATE OR REPLACE FUNCTION mtmf.guard_tenant_activation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    IF NEW.scope = 2 AND NEW.lifecycle = 1 AND OLD.lifecycle IS DISTINCT FROM 1 THEN
        IF NOT EXISTS (
            SELECT 1 FROM mtmf.stewardship_designation d WHERE d.tenant_id = NEW.id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT014',
                MESSAGE = 'an ordinary Tenant cannot become ACTIVE without a stewardship designation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenant_activation_guard
    BEFORE UPDATE ON mtmf.tenant
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_tenant_activation();

-- 7. Runtime creation of an ordinary Tenant must start PROVISIONING.
CREATE OR REPLACE FUNCTION mtmf.tenant_add(
    id_value uuid,
    name_value text,
    scope_value smallint,
    owner_identity_id_value uuid,
    lifecycle_value smallint,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF scope_value = 2 AND lifecycle_value = 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT014',
            MESSAGE = 'an ordinary Tenant must be created PROVISIONING and activated after designation';
    END IF;
    INSERT INTO mtmf.tenant (
        id, name, scope, owner_identity_id, lifecycle, deletion_status, extension
    )
    VALUES (
        id_value, name_value, scope_value, owner_identity_id_value,
        lifecycle_value, deletion_status_value, extension_value
    )
    ON CONFLICT (id) DO NOTHING;
    RETURN FOUND;
END;
$$;

-- 8. Stewardship audit is append-only.
CREATE OR REPLACE FUNCTION mtmf.guard_stewardship_audit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'MT033',
        MESSAGE = 'stewardship audit is append-only';
END;
$$;

CREATE TRIGGER stewardship_audit_update_guard
    BEFORE UPDATE ON mtmf.stewardship_audit
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_stewardship_audit();

CREATE TRIGGER stewardship_audit_delete_guard
    BEFORE DELETE ON mtmf.stewardship_audit
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_stewardship_audit();

-- 9. The designated steward's final Tenant Administrator grant cannot be
--    revoked while the designation stands. Direct and Group-derived grants
--    are both considered, matching stewardship_is_eligible.
CREATE OR REPLACE FUNCTION mtmf.guard_steward_role_assignment()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    tenant_admin_urn constant text := 'urn:mtmf:iam:roles:system:tenant-administrator';
BEGIN
    IF OLD.role_urn IS DISTINCT FROM tenant_admin_urn OR OLD.organization_id IS NOT NULL THEN
        RETURN COALESCE(NEW, OLD);
    END IF;

    IF TG_TABLE_NAME = 'identity_role_assignment' THEN
        -- Lock the subject Identity so a concurrent designation (which locks
        -- the same Identity before validating) serializes against this
        -- revocation; otherwise both could commit a write skew.
        PERFORM 1 FROM mtmf.identity WHERE id = OLD.identity_id FOR UPDATE;
        IF EXISTS (
            SELECT 1 FROM mtmf.stewardship_designation d
            WHERE d.tenant_id = OLD.tenant_id AND d.designated_identity_id = OLD.identity_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM mtmf.identity_role_assignment ira
            WHERE ira.tenant_id = OLD.tenant_id AND ira.identity_id = OLD.identity_id
              AND ira.organization_id IS NULL AND ira.id <> OLD.id
        )
        AND NOT EXISTS (
            SELECT 1
            FROM mtmf.identity_group_membership igm
            JOIN mtmf.group_role_assignment gra
              ON gra.group_id = igm.group_id AND gra.tenant_id = OLD.tenant_id
            JOIN mtmf.group g
              ON g.id = igm.group_id AND g.deletion_status = 2
            WHERE igm.identity_id = OLD.identity_id AND gra.organization_id IS NULL
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT032',
                MESSAGE = 'the designated steward final Tenant Administrator assignment cannot be removed';
        END IF;
    ELSIF TG_TABLE_NAME = 'group_role_assignment' THEN
        -- Lock every member Identity of the affected Group (deterministic id
        -- order) so a concurrent designation of any of them serializes.
        PERFORM 1 FROM mtmf.identity i
        WHERE i.id IN (
            SELECT igm.identity_id
            FROM mtmf.identity_group_membership igm
            WHERE igm.group_id = OLD.group_id
        )
        ORDER BY i.id
        FOR UPDATE;
        IF EXISTS (
            SELECT 1
            FROM mtmf.identity_group_membership igm
            JOIN mtmf.stewardship_designation d
              ON d.tenant_id = OLD.tenant_id AND d.designated_identity_id = igm.identity_id
            WHERE igm.group_id = OLD.group_id
              AND NOT EXISTS (
                  SELECT 1 FROM mtmf.identity_role_assignment ira
                  WHERE ira.tenant_id = OLD.tenant_id AND ira.identity_id = igm.identity_id
                    AND ira.organization_id IS NULL
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM mtmf.identity_group_membership igm2
                  JOIN mtmf.group_role_assignment gra2
                    ON gra2.group_id = igm2.group_id AND gra2.tenant_id = OLD.tenant_id
                  JOIN mtmf.group g2
                    ON g2.id = igm2.group_id AND g2.deletion_status = 2
                  WHERE igm2.identity_id = igm.identity_id
                    AND gra2.organization_id IS NULL
                    AND gra2.id <> OLD.id
              )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT032',
                MESSAGE = 'the designated steward final Tenant Administrator assignment cannot be removed';
        END IF;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER identity_role_assignment_steward_guard
    BEFORE DELETE OR UPDATE ON mtmf.identity_role_assignment
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_steward_role_assignment();

CREATE TRIGGER group_role_assignment_steward_guard
    BEFORE DELETE OR UPDATE ON mtmf.group_role_assignment
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_steward_role_assignment();

-- 10. A Group-derived designated steward cannot be orphaned by removing the
--     Identity's membership in the authorizing Group while the designation
--     stands and no other active Tenant Administrator source remains.
CREATE OR REPLACE FUNCTION mtmf.guard_steward_group_membership()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    group_tenant uuid;
    tenant_admin_urn constant text := 'urn:mtmf:iam:roles:system:tenant-administrator';
BEGIN
    SELECT g.tenant_id INTO group_tenant FROM mtmf.group AS g WHERE g.id = OLD.group_id;
    IF group_tenant IS NULL THEN
        RETURN OLD;
    END IF;
    -- Serialize against a concurrent designation of this Identity.
    PERFORM 1 FROM mtmf.identity WHERE id = OLD.identity_id FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.stewardship_designation d
        WHERE d.tenant_id = group_tenant AND d.designated_identity_id = OLD.identity_id
    ) THEN
        RETURN OLD;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.group_role_assignment gra
        WHERE gra.group_id = OLD.group_id AND gra.tenant_id = group_tenant
          AND gra.role_urn = tenant_admin_urn AND gra.organization_id IS NULL
    ) THEN
        RETURN OLD;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.identity_role_assignment ira
        WHERE ira.tenant_id = group_tenant AND ira.identity_id = OLD.identity_id
          AND ira.role_urn = tenant_admin_urn AND ira.organization_id IS NULL
    ) AND NOT EXISTS (
        SELECT 1
        FROM mtmf.identity_group_membership igm
        JOIN mtmf.group_role_assignment gra
          ON gra.group_id = igm.group_id AND gra.tenant_id = group_tenant
        JOIN mtmf.group g
          ON g.id = igm.group_id AND g.deletion_status = 2
        WHERE igm.identity_id = OLD.identity_id
          AND igm.group_id <> OLD.group_id
          AND gra.role_urn = tenant_admin_urn
          AND gra.organization_id IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT032',
            MESSAGE = 'the designated steward final Tenant Administrator group membership cannot be removed';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER identity_group_membership_steward_guard
    BEFORE DELETE ON mtmf.identity_group_membership
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_steward_group_membership();

-- 11. An authorizing Group cannot be deactivated/deleted while it is the
--     designated steward's final Tenant Administrator source.
CREATE OR REPLACE FUNCTION mtmf.guard_steward_group()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    tenant_admin_urn constant text := 'urn:mtmf:iam:roles:system:tenant-administrator';
BEGIN
    IF TG_OP = 'UPDATE' AND NOT (NEW.deletion_status = 1 AND OLD.deletion_status = 2) THEN
        RETURN NEW;
    END IF;
    -- Serialize against a concurrent designation of any Group member.
    PERFORM 1 FROM mtmf.identity i
    WHERE i.id IN (
        SELECT igm.identity_id
        FROM mtmf.identity_group_membership igm
        WHERE igm.group_id = OLD.id
    )
    ORDER BY i.id
    FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.group_role_assignment gra
        WHERE gra.group_id = OLD.id AND gra.tenant_id = OLD.tenant_id
          AND gra.role_urn = tenant_admin_urn AND gra.organization_id IS NULL
    ) THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF EXISTS (
        SELECT 1
        FROM mtmf.identity_group_membership igm
        JOIN mtmf.stewardship_designation d
          ON d.tenant_id = OLD.tenant_id AND d.designated_identity_id = igm.identity_id
        WHERE igm.group_id = OLD.id
          AND NOT EXISTS (
              SELECT 1 FROM mtmf.identity_role_assignment ira
              WHERE ira.tenant_id = OLD.tenant_id AND ira.identity_id = igm.identity_id
                AND ira.role_urn = tenant_admin_urn AND ira.organization_id IS NULL
          )
          AND NOT EXISTS (
              SELECT 1
              FROM mtmf.identity_group_membership igm2
              JOIN mtmf.group_role_assignment gra2
                ON gra2.group_id = igm2.group_id AND gra2.tenant_id = OLD.tenant_id
              JOIN mtmf.group g2
                ON g2.id = igm2.group_id AND g2.deletion_status = 2
              WHERE igm2.identity_id = igm.identity_id
                AND igm2.group_id <> OLD.id
                AND gra2.role_urn = tenant_admin_urn
                AND gra2.organization_id IS NULL
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT032',
            MESSAGE = 'the designated steward final Tenant Administrator group cannot be deactivated or deleted';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER steward_group_guard
    BEFORE UPDATE OR DELETE ON mtmf.group
    FOR EACH ROW EXECUTE FUNCTION mtmf.guard_steward_group();
