# When merging the FENCE (Also consider the BDC specific) specific pic-sure-auth-micro-app and the more general
# pic-sure-auth-micro-app, we need to remove the circular dependency between the access_rule table and itself.
# We could have supported both, but the same functionality is already supported by the accessRule_subRule join table.
# This script will remove the circular dependency and replace it with a reference to the join table.

-- Step 1: Insert data from the circular dependency into the join table
INSERT INTO accessRule_subRule (accessRule_id, subRule_id)
SELECT ar.uuid, ar.subAccessRuleParent_uuid
FROM access_rule ar
WHERE ar.subAccessRuleParent_uuid IS NOT NULL;

-- Step 2: Update references in the original table to point to the join table
UPDATE access_rule ar
    JOIN accessRule_subRule ars ON ars.accessRule_id = ar.uuid
    SET ar.subAccessRuleParent_uuid = NULL; -- Remove circular dependency reference so it can be dropped

-- Step 3: Drop the column from the original table
ALTER TABLE access_rule DROP COLUMN subAccessRuleParent_uuid;