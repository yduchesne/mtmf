-- v017: install exactly one approved protected Application Administrator Role.
--
-- This is policy data, not an assignment or a privilege installer. It does not
-- modify v006/v012/v016, create database roles/grants, or assign the Role.

DO $mtmf_seed_application_admin$
DECLARE
    role_urn_value constant text := 'urn:mtmf:iam:roles:system:application-administrator';
    set_id_value constant uuid := 'ef895e22-cc8b-53db-a804-7ef11cffcb60';
    permission_urns constant text[] := ARRAY[
        'urn:mtmf:iam:permissions:system:application:create-object',
        'urn:mtmf:iam:permissions:system:application:get-object',
        'urn:mtmf:iam:permissions:system:application:suspend-object',
        'urn:mtmf:iam:permissions:system:application:resume-object',
        'urn:mtmf:iam:permissions:system:application:retire-object',
        'urn:mtmf:iam:permissions:system:application-tenant-registration:add-object',
        'urn:mtmf:iam:permissions:system:application-tenant-registration:get-object',
        'urn:mtmf:iam:permissions:system:application-tenant-registration:revoke-object',
        'urn:mtmf:iam:permissions:system:application-onboarding-entitlement:grant-object',
        'urn:mtmf:iam:permissions:system:application-onboarding-entitlement:revoke-object',
        'urn:mtmf:iam:permissions:system:application-onboarding-entitlement:get-object'
    ];
    permission_ids constant uuid[] := ARRAY[
        '25a2f2f4-f32d-5447-bf39-578b4b4c312c',
        'da26e3bd-b3cb-5232-9910-3bc5b7f7fdda',
        '1ed11804-0a69-5a0f-89eb-3665b7c6cef4',
        '84ec050a-8732-51c5-9ca0-304e8347f642',
        '62ce5487-bbb9-5c3b-ae91-d6fcd560a7bf',
        'ca253e75-2bb6-58c1-88db-02a191412018',
        '49b322cf-6b12-5ec2-ae07-71aa541280c8',
        'ea1a042a-dc5a-5e5c-aab9-a19d995d2e58',
        '909403b6-cb5c-5722-91f6-fac47e86fb15',
        '4a07317d-5c71-5118-9b95-899745a404f9',
        '77915183-0f56-5329-8669-f1958d354cf1'
    ];
    role_present boolean;
    marker_present boolean;
    set_count integer;
    permission_count integer;
    i integer;
    expected_action text;
    action_count integer;
BEGIN
    SELECT EXISTS (SELECT 1 FROM mtmf.role WHERE urn = role_urn_value) INTO role_present;
    SELECT EXISTS (SELECT 1 FROM mtmf.builtin_role WHERE role_urn = role_urn_value)
      INTO marker_present;

    IF EXISTS (SELECT 1 FROM mtmf.permission_set WHERE id = set_id_value AND role_urn <> role_urn_value) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017: approved PermissionSet UUID collides with another Role';
    END IF;
    FOR i IN 1..array_length(permission_ids, 1) LOOP
        IF EXISTS (
            SELECT 1 FROM mtmf.permission
             WHERE id = permission_ids[i]
               AND (permission_set_id <> set_id_value OR urn <> permission_urns[i] OR position <> i - 1)
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT010',
                MESSAGE = '0017: approved Permission UUID collides with a different row';
        END IF;
    END LOOP;

    IF role_present THEN
        IF NOT marker_present THEN
            RAISE EXCEPTION USING ERRCODE = 'MT010',
                MESSAGE = '0017: existing Application Administrator Role is not a protected builtin';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM mtmf.role
             WHERE urn = role_urn_value
               AND name = 'Application Administrator'
               AND description = ''
               AND defining_tenant_id IS NULL
               AND extension = '{}'::jsonb
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT010',
                MESSAGE = '0017: existing Application Administrator Role metadata is not approved';
        END IF;
        SELECT count(*) INTO set_count FROM mtmf.permission_set WHERE role_urn = role_urn_value;
        IF set_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM mtmf.permission_set
             WHERE id = set_id_value AND role_urn = role_urn_value
               AND effect = 'allow' AND position = 0
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT010',
                MESSAGE = '0017: existing Application Administrator PermissionSet is not approved';
        END IF;
        SELECT count(*) INTO permission_count
          FROM mtmf.permission p
          JOIN mtmf.permission_set ps ON ps.id = p.permission_set_id
         WHERE ps.role_urn = role_urn_value;
        IF permission_count <> 11 THEN
            RAISE EXCEPTION USING ERRCODE = 'MT010',
                MESSAGE = '0017: existing Application Administrator must own exactly 11 Permissions';
        END IF;
        FOR i IN 1..array_length(permission_ids, 1) LOOP
            IF NOT EXISTS (
                SELECT 1 FROM mtmf.permission AS p
                 WHERE p.id = permission_ids[i]
                   AND p.permission_set_id = set_id_value
                   AND p.urn = permission_urns[i]
                   AND p.position = i - 1
            ) THEN
                RAISE EXCEPTION USING ERRCODE = 'MT010',
                    MESSAGE = '0017: existing Application Administrator Permission tuple is not approved';
            END IF;
            expected_action := replace(permission_urns[i], 'urn:mtmf:iam:permissions:', 'urn:mtmf:iam:actions:');
            SELECT count(*) INTO action_count FROM mtmf.action WHERE urn = expected_action;
            IF action_count <> 1 THEN
                RAISE EXCEPTION USING ERRCODE = 'MT010',
                    MESSAGE = '0017: required Application Administrator Action is missing';
            END IF;
        END LOOP;
        RETURN;
    END IF;

    IF marker_present THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017: builtin marker exists without its Role';
    END IF;
    IF EXISTS (SELECT 1 FROM mtmf.permission_set WHERE id = set_id_value)
       OR EXISTS (SELECT 1 FROM mtmf.permission WHERE id = ANY(permission_ids)) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017: a proposed seed UUID is already in use';
    END IF;

    FOR i IN 1..array_length(permission_urns, 1) LOOP
        expected_action := replace(permission_urns[i], 'urn:mtmf:iam:permissions:', 'urn:mtmf:iam:actions:');
        INSERT INTO mtmf.action (urn) VALUES (expected_action)
        ON CONFLICT (urn) DO NOTHING;
    END LOOP;

    INSERT INTO mtmf.role (urn, name, description, defining_tenant_id, extension)
    VALUES (role_urn_value, 'Application Administrator', '', NULL, '{}'::jsonb);

    INSERT INTO mtmf.permission_set (id, role_urn, effect, position)
    VALUES (set_id_value, role_urn_value, 'allow', 0);

    FOR i IN 1..array_length(permission_urns, 1) LOOP
        INSERT INTO mtmf.permission (id, permission_set_id, urn, position)
        VALUES (permission_ids[i], set_id_value, permission_urns[i], i - 1);
    END LOOP;

    INSERT INTO mtmf.builtin_role (role_urn) VALUES (role_urn_value);

    -- Re-read the exact installed aggregate before the independent assertions.
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.role
         WHERE urn = role_urn_value
           AND name = 'Application Administrator'
           AND description = ''
           AND defining_tenant_id IS NULL
           AND extension = '{}'::jsonb
    ) OR NOT EXISTS (
        SELECT 1 FROM mtmf.builtin_role WHERE role_urn = role_urn_value
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017: installed Application Administrator seed is incomplete';
    END IF;
    SELECT count(*) INTO permission_count
      FROM mtmf.permission p
      JOIN mtmf.permission_set ps ON ps.id = p.permission_set_id
     WHERE ps.role_urn = role_urn_value;
    IF permission_count <> 11 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017: installed Application Administrator must have 11 Permissions';
    END IF;
END
$mtmf_seed_application_admin$;
