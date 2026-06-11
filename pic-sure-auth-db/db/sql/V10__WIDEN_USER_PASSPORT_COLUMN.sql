-- Direct RAS userinfo removes Okta's attribute-length ceiling on the mapped passport claim.
-- Multi-visa passports with large dbGaP permission lists can exceed TEXT (64KB); MEDIUMTEXT (16MB)
-- removes the practical limit. (general_metadata at varchar(9000) is unaffected: the new
-- researcher_role/federated fields add at most a few hundred bytes.)
ALTER TABLE user MODIFY COLUMN passport MEDIUMTEXT;
