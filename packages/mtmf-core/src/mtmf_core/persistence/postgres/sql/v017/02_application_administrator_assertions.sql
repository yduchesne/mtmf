-- v017: independent post-conditions for the approved Application Administrator seed.

DO $mtmf_assert_application_admin$
DECLARE
    role_urn_value constant text := 'urn:mtmf:iam:roles:system:application-administrator';
    set_id_value constant uuid := 'ef895e22-cc8b-53db-a804-7ef11cffcb60';
    expected_urns constant text[] := ARRAY[
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
    expected_ids constant uuid[] := ARRAY[
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
    actual_count integer;
    i integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM mtmf.role
         WHERE urn = role_urn_value
           AND name = 'Application Administrator'
           AND description = ''
           AND defining_tenant_id IS NULL
           AND extension = '{}'::jsonb
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017 assertion: Role metadata is not exact';
    END IF;
    IF (SELECT count(*) FROM mtmf.builtin_role WHERE role_urn = role_urn_value) <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017 assertion: protected marker is missing or duplicated';
    END IF;
    IF (SELECT count(*) FROM mtmf.permission_set WHERE role_urn = role_urn_value) <> 1
       OR NOT EXISTS (
           SELECT 1 FROM mtmf.permission_set
            WHERE id = set_id_value AND role_urn = role_urn_value
              AND effect = 'allow' AND position = 0
       ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017 assertion: PermissionSet is not the single approved ALLOW set';
    END IF;
    SELECT count(*) INTO actual_count
      FROM mtmf.permission p
      JOIN mtmf.permission_set ps ON ps.id = p.permission_set_id
     WHERE ps.role_urn = role_urn_value;
    IF actual_count <> 11 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017 assertion: Permission count is not exactly 11';
    END IF;
    FOR i IN 1..11 LOOP
        IF NOT EXISTS (
            SELECT 1 FROM mtmf.permission
             WHERE id = expected_ids[i]
               AND permission_set_id = set_id_value
               AND urn = expected_urns[i]
               AND position = i - 1
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT010',
                MESSAGE = '0017 assertion: approved Permission tuple is missing or altered';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM mtmf.action
             WHERE urn = replace(expected_urns[i], 'urn:mtmf:iam:permissions:', 'urn:mtmf:iam:actions:')
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT010',
                MESSAGE = '0017 assertion: corresponding Action is missing';
        END IF;
    END LOOP;
    IF EXISTS (
        SELECT 1
          FROM mtmf.role r
          JOIN mtmf.permission_set ps ON ps.role_urn = r.urn
          JOIN mtmf.permission p ON p.permission_set_id = ps.id
         WHERE r.urn = role_urn_value
           AND (p.position < 0 OR p.position > 10 OR p.urn LIKE '%*%')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010',
            MESSAGE = '0017 assertion: wildcard or out-of-range Permission exists';
    END IF;
END
$mtmf_assert_application_admin$;
