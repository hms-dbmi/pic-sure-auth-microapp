DROP PROCEDURE IF EXISTS CreateUserWithRole;
delimiter //
CREATE PROCEDURE CreateUserWithRole (
    IN user_email VARCHAR(255),
    IN connection_id VARCHAR(255),
    IN role_name VARCHAR(255)
)
BEGIN
SELECT @userUUID := uuid FROM auth.user WHERE email = user_email AND connectionId = connection_id;
SELECT @roleUUID := uuid FROM auth.role WHERE name = role_name;
IF @userUUID IS NULL THEN
        SET @userUUID = UNHEX(REPLACE(UUID(), '-', ''));
SELECT @connectionUUID := uuid FROM auth.connection WHERE id = connection_id;
INSERT INTO auth.user (uuid, general_metadata, acceptedTOS, connectionId, email, matched, subject, is_active, long_term_token, isGateAnyRelation)
VALUES (@userUUID, null, (SELECT CURRENT_TIMESTAMP), @connectionUUID, user_email, 0, null, 1, null, 1);
END IF;
    IF @roleUUID IS NOT NULL THEN
        INSERT INTO auth.user_role (user_id, role_id) VALUES (@userUUID, @roleUUID);
END IF;
END//
delimiter;