use auth;
-- Add access rule to allow access to /query/{queryId}/metadata
SET @uuidGate = REPLACE(uuid(),'-','');
INSERT INTO access_rule (uuid, name, description, rule, type, value, checkMapKeyOnly, checkMapNode, subAccessRuleParent_uuid, isEvaluateOnlyByGates, isGateAnyRelation)
VALUES (
   unhex(@uuidGate),
   'ALLOW_METADATA_ACCESS',
   'Allow access to metadata endpoint',
   '$.path',
   11,
   '/query/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/metadata',
   false,
   true,
   NULL,
   true,
   false
);

INSERT INTO accessRule_privilege (privilege_id, accessRule_id)
SELECT privilege.uuid, unhex(@uuidGate) from privilege, role_privilege, role
where privilege.uuid = role_privilege.privilege_id
  AND role_privilege.role_id = role.uuid
  AND role.name = 'FENCE_ROLE_OPEN_ACCESS';