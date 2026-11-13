-- v016: fail-closed post-conditions. Control-role grants are not asserted as
-- present: migration 0016 must succeed with the control role absent.

DO $pr24p_assertions$
DECLARE
    signature text;
    function_oid oid;
    role_oid oid;
BEGIN
    FOREACH signature IN ARRAY ARRAY[
        'mtmf.control_entitlement_grant(uuid,uuid,text,text,uuid,uuid,bigint,text,uuid,bytea)',
        'mtmf.control_entitlement_revoke(uuid,uuid,text,text,uuid,uuid,text,uuid,bytea)',
        'mtmf.control_entitlement_get(uuid,uuid,text,text,uuid,uuid)',
        'mtmf.control_operator_authorization_snapshot(uuid,uuid,text,text,uuid,uuid)',
        'mtmf.control_pre_tenant_admission_read(uuid,text,text)'
    ]
    LOOP
        function_oid := to_regprocedure(signature);
        IF function_oid IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MT049',
                MESSAGE = 'v016: missing PR24P private function ' || signature;
        END IF;
        IF pg_catalog.pg_get_userbyid((SELECT proowner FROM pg_catalog.pg_proc WHERE oid = function_oid)) <> 'mtmf_owner' THEN
            RAISE EXCEPTION USING ERRCODE = 'MT049',
                MESSAGE = 'v016: PR24P function is not owner-owned: ' || signature;
        END IF;
        IF NOT (SELECT prosecdef FROM pg_catalog.pg_proc WHERE oid = function_oid) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT049',
                MESSAGE = 'v016: PR24P function is not SECURITY DEFINER: ' || signature;
        END IF;
        IF has_function_privilege('public', function_oid, 'EXECUTE') THEN
            RAISE EXCEPTION USING ERRCODE = 'MT049',
                MESSAGE = 'v016: PUBLIC can EXECUTE ' || signature;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mtmf_runtime')
           AND has_function_privilege('mtmf_runtime', function_oid, 'EXECUTE') THEN
            RAISE EXCEPTION USING ERRCODE = 'MT049',
                MESSAGE = 'v016: mtmf_runtime can EXECUTE ' || signature;
        END IF;
    END LOOP;

    IF (SELECT provolatile FROM pg_catalog.pg_proc
             WHERE oid = to_regprocedure('mtmf.control_pre_tenant_admission_read(uuid,text,text)')) <> 's' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT049',
            MESSAGE = 'v016: admission read must be STABLE';
    END IF;

    FOREACH signature IN ARRAY ARRAY[
        'mtmf.system_operator_assignment',
        'mtmf.system_operator_assignment_event',
        'mtmf.system_operator_execution',
        'mtmf.system_operator_execution_audit'
    ]
    LOOP
        IF pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = to_regclass(signature))) <> 'mtmf_owner' THEN
            RAISE EXCEPTION USING ERRCODE = 'MT049',
                MESSAGE = 'v016: table is not owner-owned: ' || signature;
        END IF;
        IF has_table_privilege('public', signature, 'SELECT')
           OR has_table_privilege('public', signature, 'INSERT')
           OR has_table_privilege('public', signature, 'UPDATE')
           OR has_table_privilege('public', signature, 'DELETE') THEN
            RAISE EXCEPTION USING ERRCODE = 'MT049',
                MESSAGE = 'v016: PUBLIC has table privileges on ' || signature;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mtmf_runtime')
           AND (has_table_privilege('mtmf_runtime', signature, 'SELECT')
                OR has_table_privilege('mtmf_runtime', signature, 'INSERT')
                OR has_table_privilege('mtmf_runtime', signature, 'UPDATE')
                OR has_table_privilege('mtmf_runtime', signature, 'DELETE')) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT049',
                MESSAGE = 'v016: mtmf_runtime has table privileges on ' || signature;
        END IF;
    END LOOP;

    -- If a control role already exists, the migration must not have granted it
    -- any EXECUTE. Installation grants are a separate phase.
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mtmf_control_exec'
    ) THEN
        FOR function_oid IN
            SELECT p.oid
              FROM pg_catalog.pg_proc p
              JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'mtmf'
               AND p.proname IN (
                   'control_entitlement_grant',
                   'control_entitlement_revoke',
                   'control_entitlement_get',
                   'control_operator_authorization_snapshot',
                   'control_pre_tenant_admission_read'
               )
        LOOP
            IF has_function_privilege('mtmf_control_exec', function_oid, 'EXECUTE') THEN
                RAISE EXCEPTION USING ERRCODE = 'MT049',
                    MESSAGE = 'v016: migration granted control EXECUTE (installation phase required): '
                              || function_oid::regprocedure::text;
            END IF;
        END LOOP;
    END IF;
END
$pr24p_assertions$;
