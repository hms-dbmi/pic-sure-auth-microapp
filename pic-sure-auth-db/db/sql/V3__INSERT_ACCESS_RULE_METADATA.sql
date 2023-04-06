--  This SQL script adds an access_rule to the auth database that allows access to the /query/{queryId}/metadata
--  endpoint for requests that include a UUID in the path. The rule field specifies that the rule should be evaluated
--  based on the path field of the request. The type field is set to 11, which specifies that the value field should be
--  treated as a regular expression. The value field contains a regular expression that matches UUIDs in the
--  /query/{queryId}/metadata endpoint path. The isEvaluateOnlyByGates field is set to true, which means that the rule
--  will only be evaluated by gate rules and not by any other rules. The isGateAnyRelation field is set to false,
--  which means that all of the gates in the rule must evaluate to true for the rule to be considered a match.
--  The subAccessRuleParent_uuid field is set to NULL, which means that the rule does not have any sub-rules associated
--  with it. The checkMapKeyOnly field is set to false, which means that the rule will be evaluated against the entire
--  request path. The checkMapNode field is set to true, which means that the rule will be evaluated against the
--  request path as a map node.

use auth;
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