# Authorization System Documentation

## Overview

This document provides comprehensive documentation on how Roles, Privileges, and AccessRules are created and managed in the PIC-SURE Auth Microapp. These components form the core of the authorization system, controlling what resources users can access and what actions they can perform.

## Table of Contents

1. [Entity Relationships](#entity-relationships)
2. [Roles](#roles)
   - [What is a Role?](#what-is-a-role)
   - [Role Properties](#role-properties)
   - [Types of Roles](#types-of-roles)
3. [Privileges](#privileges)
   - [What is a Privilege?](#what-is-a-privilege)
   - [Privilege Properties](#privilege-properties)
   - [Types of Privileges](#types-of-privileges)
4. [Access Rules](#access-rules)
   - [What is an Access Rule?](#what-is-an-access-rule)
   - [Access Rule Properties](#access-rule-properties)
   - [Types of Access Rules](#types-of-access-rules)
   - [AccessRules for Each Privilege Type](#accessrules-for-each-privilege-type)
   - [Complex Rules with Gates and Sub-Rules](#complex-rules-with-gates-and-sub-rules)
5. [Access Rule Evaluation](#access-rule-evaluation)
   - [Evaluation Flow](#evaluation-flow)
   - [Individual AccessRule Evaluation](#individual-accessrule-evaluation)
   - [JSON Examples](#json-examples)
   - [Understanding AccessRule Types](#understanding-accessrule-types)
   - [Understanding Rule Pass/Fail Results](#understanding-rule-passfail-results)
   - [Privilege Evaluation Against JSON Queries](#privilege-evaluation-against-json-queries)
6. [Creating and Managing Authorization Components](#creating-and-managing-authorization-components)
7. [Cross Consent Variables](#cross-consent-variables)
   - [What are Cross Consent Variables?](#what-are-cross-consent-variables)
   - [How Cross Consent Variables are Implemented](#how-cross-consent-variables-are-implemented)
   - [Harmonized Sub-Rules for Cross-Study Analysis](#harmonized-sub-rules-for-cross-study-analysis)
   - [Technical Implementation Details](#technical-implementation-details)
   - [Example JSON Query for Cross Consent Analysis](#example-json-query-for-cross-consent-analysis)
   - [Key Characteristics of Cross Consent Handling](#key-characteristics-of-cross-consent-handling)
8. [Best Practices](#best-practices)

## Entity Relationships

The authorization system consists of three main entities with the following relationships:

- **User** has many **Roles**
- **Role** has many **Privileges**
- **Privilege** has many **AccessRules**
- **AccessRule** can have many **Gates** (which are also AccessRules)
- **AccessRule** can have many **SubAccessRules** (which are also AccessRules)

### Entity Relationship Diagram

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│    User     │───┬───│    Role     │───────│  Privilege  │───────│ AccessRule  │
└─────────────┘   │   └─────────────┘       └─────────────┘       └─────────────┘
                  │                                                      │
                  │                                                      │
                  │   ┌─────────────┐                            ┌───────┴───────┐
                  └───│ Public Role │                            │               │
                      └─────────────┘                            ▼               ▼
                                                          ┌─────────────┐ ┌─────────────┐
                                                          │    Gates    │ │  Sub-Rules  │
                                                          └─────────────┘ └─────────────┘
```

This hierarchical structure allows for fine-grained access control:
1. Users are assigned Roles
2. Roles contain Privileges
3. Privileges are enforced through AccessRules
4. AccessRules can be combined using gates and sub-rules for complex authorization logic

## Roles

### What is a Role?

A Role represents a set of permissions assigned to users. It groups related privileges together to simplify access management. Instead of assigning individual privileges to each user, administrators can assign roles.

### Role Properties

- **UUID**: Unique identifier
- **Name**: Role name (e.g., "ADMIN", "MANAGED_phs000123_c1")
- **Description**: Human-readable description of the role
- **Privileges**: Set of privileges associated with this role
- **Version**: Version number for tracking changes

### Types of Roles

- **System Roles**: Pre-defined roles like ADMIN
- **Managed Roles**: Automatically generated roles based on study metadata (e.g., "MANAGED_phs000123_c1")
- **Manual Roles**: Custom roles created for specific purposes

## Privileges

### What is a Privilege?

A Privilege defines a specific permission within the system. It contains query templates and scopes that define what data can be accessed, and is enforced through a set of access rules.

### Privilege Properties

- **UUID**: Unique identifier
- **Name**: Privilege name (e.g., "PRIV_MANAGED_phs000123_c1")
- **Description**: Human-readable description
- **Application**: Associated application
- **QueryTemplate**: JSON template defining allowed queries
- **QueryScope**: JSON array defining the scope of allowed queries
- **AccessRules**: Set of access rules that enforce this privilege

### Types of Privileges

- **Clinical Privileges**: Control access to clinical data
  - **Parent**: Access to parent study data
  - **Harmonized**: Access to harmonized study data
- **Topmed Privileges**: Control access to genomic data
  - **Topmed Only**: Access to genomic data only
  - **Topmed + Parent**: Access to genomic and parent clinical data
  - **Topmed + Harmonized**: Access to genomic and harmonized clinical data

#### Privilege Types Relationship Diagram

```
┌───────────────────────────────────────────────────────────────────┐
│                           Privileges                               │
└───────────────────────────────────────────────────────────────────┘
                  │                           │
        ┌─────────┴──────────┐      ┌────────┴─────────┐
        │                    │      │                  │
┌───────▼───────┐    ┌───────▼───────┐      ┌─────────▼────────┐
│   Clinical    │    │   Clinical    │      │      Topmed      │
│ Non-Harmonized│    │   Harmonized  │      │    Privileges    │
└───────────────┘    └───────────────┘      └──────────────────┘
        │                   │                        │
        │                   │                        │
┌───────▼───────┐   ┌───────▼───────┐      ┌────────▼─────────┐
│ Parent Access │   │Parent + Harm. │      │ Topmed Access    │
│    Rules      │   │Access Rules   │      │     Rules        │
└───────────────┘   └───────────────┘      └──────────────────┘
                                                    │
                                           ┌────────┴─────────┐
                                           │                  │
                                    ┌──────▼─────┐    ┌───────▼──────┐
                                    │  Topmed    │    │Topmed + Harm.│
                                    │   Only     │    │              │
                                    └────────────┘    └──────────────┘
```

This diagram illustrates how different privilege types relate to each other and what access rules they contain. Clinical privileges are divided into non-harmonized and harmonized types, while Topmed privileges can include access to genomic data only or in combination with clinical data.

## Access Rules

### What is an Access Rule?

An AccessRule is the most granular component of the authorization system. It defines specific conditions that must be met for a user to access certain data or perform certain actions. Access rules use JSONPath expressions to evaluate requests against allowed values.

### Access Rule Properties

- **UUID**: Unique identifier
- **Name**: Rule name
- **Description**: Human-readable description
- **Rule**: JSONPath expression to retrieve values from requests
- **Type**: Type of evaluation (e.g., CONTAINS, EQUALS, REGEX_MATCH)
- **Value**: Value to compare against
- **CheckMapNode**: Flag to check all nodes in a map
- **CheckMapKeyOnly**: Flag to check only map keys
- **Gates**: Set of other access rules that act as gates
- **GateAnyRelation**: Flag to determine if gates have an ANY (OR) or ALL (AND) relationship
- **EvaluateOnlyByGates**: Flag to evaluate based solely on gates
- **SubAccessRule**: Set of sub-rules for complex nested conditions

### Types of Access Rules

- **Consent Access Rules**: Check if a user has consent to access specific study data
- **Clinical Access Rules**: Control access to clinical data
- **Topmed Access Rules**: Control access to genomic data
- **Gate Rules**: Used to create complex logical conditions (AND/OR)
- **Standard Access Rules**: Common rules applied to multiple privileges

### AccessRules for Each Privilege Type

This section outlines all the specific AccessRules that are created for each privilege type, including their name, rule, type, and value, along with an explanation of their purpose.

#### Clinical Privileges (Non-Harmonized)

Clinical privileges for non-harmonized studies include the following AccessRules:

1. **Parent Access Rule**:
   - **Name**: `AR_CONSENT_<studyId>_<consentGroup>_PARENT`
   - **Rule**: `$.query.categoryFilters.\\_consents\\[*]`
   - **Type**: ALL_EQUALS (4)
   - **Value**: `<studyId>.<consentGroup>`
   - **Purpose**: Ensures the query is accessing only the parent study data for the specific study and consent group.

2. **Topmed Parent Access Rule**:
   - **Name**: `AR_TOPMED_<studyId>_<consentGroup>_TOPMED+PARENT`
   - **Rule**: [Complex, with gates and sub-rules](#complex-rules-with-gates-and-sub-rules)
   - **Purpose**: Ensures the query doesn't include genomic filters when accessing clinical data. This is a complex rule with gates and sub-rules that check for the absence of variant info filters.

3. **Standard Access Rules**:
   - **Purpose**: Common rules applied to all privileges, including:
     - Allowed query types (COUNT, CROSS_COUNT, etc.) See the application properties for a complete list.
     - Field restrictions
     - Other standard constraints

#### Clinical Privileges (Harmonized)

Clinical privileges for harmonized studies include all the rules from non-harmonized studies, plus:

1. **Harmonized Access Rule**:
   - **Name**: `AR_CONSENT_<studyId>_<consentGroup>_HARMONIZED`
   - **Rule**: `$.query.categoryFilters.\\_harmonized_consent\\[*]`
   - **Type**: ALL_EQUALS (4)
   - **Value**: `<studyId>.<consentGroup>`
   - **Purpose**: Ensures the query is accessing harmonized data for the specific study and consent group.

#### Topmed Privileges

Topmed privileges include the following AccessRules:

1. **Topmed Access Rule**:
   - **Name**: `AR_TOPMED_<studyId>_<consentGroup>`
   - **Rule**: `$.query.categoryFilters.\\_topmed_consents\\[*]`
   - **Type**: ALL_EQUALS (4)
   - **Value**: `<studyId>.<consentGroup>`
   - **Purpose**: Ensures the query is accessing Topmed data for the specific study and consent group.

2. **Topmed Parent Access Rule** (if parent concept path exists):
   - **Name**: `AR_TOPMED_<studyId>_<consentGroup>_TOPMED+PARENT`
   - **Rule**: [Complex, with gates and sub-rules](#complex-rules-with-gates-and-sub-rules)
   - **Purpose**: Allows access to both Topmed and parent clinical data. This rule has gates that check for the presence of Topmed consent and sub-rules that validate the parent data access.

3. **Harmonized Topmed Access Rule** (if harmonized):
   - **Name**: `AR_TOPMED_<studyId>_<consentGroup>_HARMONIZED`
   - **Rule**: [Complex, with gates and sub-rules](#complex-rules-with-gates-and-sub-rules)
   - **Purpose**: Allows access to both Topmed and harmonized data. This rule has gates that check for the presence of Topmed consent and sub-rules that validate the harmonized data access.

4. **Standard Access Rules**:
   - **Purpose**: Same as for clinical privileges.

#### Gate Rules

Many of the above AccessRules use gates to create complex logical conditions. Common gate rules include:

1. **Consent Gate**:
   - **Name**: `GATE_CONSENT_<studyId>_<consentGroup>`
   - **Rule**: `$.query.categoryFilters.\\_consents\\[*]`
   - **Type**: ALL_EQUALS (4)
   - **Value**: `<studyId>.<consentGroup>`
   - **Purpose**: Checks if the query is accessing the specific consent group.

2. **Harmonized Consent Gate**:
   - **Name**: `GATE_HARMONIZED_CONSENT`
   - **Rule**: `$.query.categoryFilters.\\_harmonized_consent\\[*]`
   - **Type**: ALL_EQUALS (4)
   - **Value**: `<studyId>.<consentGroup>`
   - **Purpose**: Checks if the query is accessing harmonized data.

3. **Topmed Consent Gate**:
   - **Name**: `GATE_TOPMED_CONSENT`
   - **Rule**: `$.query.categoryFilters.\\_topmed_consents\\[*]`
   - **Type**: ALL_EQUALS (4)
   - **Value**: `<studyId>.<consentGroup>`
   - **Purpose**: Checks if the query is accessing Topmed data.

#### Sub-Rules

AccessRules often include sub-rules for more complex conditions. Common sub-rules include:

1. **Allowed Query Type Rules**:
   - **Name**: `AR_ALLOW_<queryType>`
   - **Rule**: `$.query.expectedResultType`
   - **Type**: ALL_EQUALS (4)
   - **Value**: `<queryType>` (e.g., "COUNT", "CROSS_COUNT")
   - **Purpose**: Ensures the query is of an allowed type.

2. **Phenotype Sub-Rules**:
   - **Purpose**: Validate access to phenotypic data, including field restrictions and concept path validations.

3. **Topmed Restricted Sub-Rules**:
   - **Purpose**: Prevent access to certain genomic data when using clinical privileges.

#### Complex Rules with Gates and Sub-Rules

Some AccessRules are particularly complex, using a combination of gates and sub-rules to enforce sophisticated access control policies. This section explains the three main types of complex rules in detail.

##### Complex Rules Structure Diagram

```
┌───────────────────────────────────────────────────────────────┐
│                      Complex Access Rule                      │
└───────────────────────────────────────────────────────────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
        ┌────────▼────────┐        ┌─────────▼─────────┐
        │      Gates      │        │     Main Rule     │
        └─────────────────┘        └───────────────────┘
                 │                           │
     ┌───────────┴───────────┐     ┌────────┴────────┐
     │                       │     │                 │
┌────▼─────┐  ┌────────┐ ┌───▼───┐ │  ┌─────────────▼──────────┐
│ Gate 1   │  │ Gate 2 │ │Gate 3 │ │  │       Sub-Rules        │
│(Consent) │  │(Type)  │ │(Field)│ │  └────────────────────────┘
└──────────┘  └────────┘ └───────┘ │             │
        │          │         │     │    ┌────────┴────────┐
        └──────────┼─────────┘     │    │                 │
                   │               │ ┌──▼───┐  ┌─────┐ ┌──▼───┐
          ┌────────▼────────┐      │ │Rule 1│  │Rule2│ │Rule 3│
          │  Gate Relation  │      │ └──────┘  └─────┘ └──────┘
          │ ┌────────────┐  │      │
          │ │gateAnyRelation│      │
          │ └────────────┘  │      │
          └─────────────────┘      │
                   │               │
                   ▼               │
          ┌────────────────┐       │
          │  Gate Result   │       │
          │  ┌─────────┐   │       │
          │  │AND or OR│   │       │
          │  └─────────┘   │       │
          └────────────────┘       │
                   │               │
                   └───────────────┘
                                  │
                                  ▼
                           ┌──────────────┐
                           │  Evaluation  │
                           │    Result    │
                           └──────────────┘
```

This diagram illustrates the structure of a complex access rule with gates and sub-rules, highlighting the AND/OR relationship between gates. The key components are:

1. **Gates**: Individual conditions that must be evaluated first
2. **Gate Relation**: Determined by the `gateAnyRelation` property:
   - If `gateAnyRelation = false` (default): Gates have an AND relationship (all must pass)
   - If `gateAnyRelation = true`: Gates have an OR relationship (at least one must pass)
3. **Main Rule**: Evaluated only if gates pass
4. **Sub-Rules**: Additional conditions that must all pass for the rule to pass

The gates evaluation process works as follows:
- For AND relationship (default): If any gate fails, the entire rule fails
- For OR relationship: If any gate passes, gate evaluation passes
- If `evaluateOnlyByGates = true`: The result is determined solely by gate evaluation
- Otherwise: If gates pass, the main rule and sub-rules are evaluated

##### Clinical Topmed Parent Access Rule

The Clinical Topmed Parent Access Rule (`AR_TOPMED_<studyId>_<consentGroup>_TOPMED+PARENT`) is used in clinical privileges to ensure that queries don't include genomic filters when accessing clinical data. It is configured as follows:

1. **Gates**:
   - **Parent Consent Gate**: Checks if the query includes the parent consent group (`GATE_PARENT_CONSENT_PRESENT`)
   - **Harmonized Consent Gate**: Checks if the query includes harmonized consent (always set to false for this rule) (`GATE_HARMONIZED_CONSENT_MISSING`)
   - **Topmed Consent Gate**: Checks if the query includes Topmed consent (always set to true for this rule) (`GATE_TOPMED_CONSENT_PRESENT`)

2. **Sub-Rules**:
   - **Allowed Query Type Rules**: Ensure the query type is one of the allowed types (e.g., COUNT, CROSS_COUNT)
   - **Phenotype Sub-Rules**: Validate access to phenotypic data, including:
     - Parent Consent Rule: Ensures the query includes the parent consent group
     - Underscore Field Rules: Validate access to specific underscore fields
   - **Topmed Consent Rule**: A special rule that allows the presence of Topmed consent in the query

This rule works by first checking if the gates pass (parent consent present, harmonized consent missing, Topmed consent present), and then evaluating the sub-rules to ensure the query is valid for clinical data access.

###### How the Clinical Topmed Parent Access Rule Blocks Genomic Filters

The Clinical Topmed Parent Access Rule works in conjunction with the Clinical Parent Access Rule to block access to genomic filters when accessing clinical data. Here's how this blocking mechanism works:

1. **Clinical Parent Access Rule**:
   - Has gates that require parent consent and disallow both harmonized and topmed consent
   - Has sub-rules that include topmed restricted sub-rules, which block genomic filters by requiring `variantInfoFilters` to be empty
   - These topmed restricted sub-rules specifically check:
     - `$.query.query.variantInfoFilters[*].categoryVariantInfoFilters.*` (must be empty)
     - `$.query.query.variantInfoFilters[*].numericVariantInfoFilters.*` (must be empty)

2. **Clinical Topmed Parent Access Rule**:
   - Has gates that require both parent consent and topmed consent, but disallow harmonized consent
   - Has sub-rules that include phenotype sub-rules, but not topmed restricted sub-rules
   - Adds a special rule to allow topmed consent in the query

When a user has a clinical privilege, both rules are added to the privilege, but they have an OR relationship during evaluation. This means that a query will pass if either rule passes:

- If the query includes only parent consent (no topmed consent) and no genomic filters, it will pass the Clinical Parent Access Rule.
- If the query includes both parent and topmed consent but no genomic filters, it will pass the Clinical Topmed Parent Access Rule.
- If the query includes genomic filters, it will fail both rules:
  - It will fail the Clinical Parent Access Rule because of the topmed restricted sub-rules
  - It will fail the Clinical Topmed Parent Access Rule because it doesn't have any special handling for genomic filters

This is how the system effectively blocks access to genomic filters when accessing clinical data, even when the query includes topmed consent.

###### Behavior When Combined with Topmed Privileges

When a user has both clinical privileges and topmed privileges for the same study, the behavior changes:

1. **Clinical Privileges** (as described above) block access to genomic filters.

2. **Topmed Privileges** include up to three access rules:
   - **Topmed Only**: Allows access to genomic data only
   - **Topmed + Parent**: Allows access to both genomic and parent clinical data
   - **Topmed + Harmonized**: Allows access to both genomic and harmonized clinical data (if the study is harmonized)

When evaluating a query, the system checks all privileges that the user has for the requested application. If any privilege's access rules pass, the query is authorized. This means:

- A query with genomic filters will be blocked by clinical privileges, but may be allowed by topmed privileges if the user has them.
- A query with both clinical data and genomic filters will be allowed only if the user has topmed privileges with the appropriate access rules (Topmed + Parent or Topmed + Harmonized).

This design ensures that users can only access genomic data if they have the appropriate topmed privileges, even if they also have clinical privileges for the same study.

##### Topmed Parent Access Rule

The Topmed Parent Access Rule (`AR_TOPMED_<studyId>_<consentGroup>_TOPMED+PARENT`) is used in Topmed privileges to allow access to both Topmed and parent clinical data. It is configured as follows:

1. **Gates**:
   - **Parent Consent Gate**: Checks if the query includes the parent consent group (set to true for this rule)
   - **Harmonized Consent Gate**: Checks if the query includes harmonized consent (set to false for this rule)
   - **Topmed Consent Gate**: Checks if the query includes Topmed consent (set to true for this rule)

2. **Sub-Rules**:
   - **Allowed Query Type Rules**: Ensure the query type is one of the allowed types
   - **Phenotype Sub-Rules**: Validate access to phenotypic data
   - **Topmed Consent Rule**: Allows the presence of Topmed consent in the query

This rule works by first checking if the gates pass (both parent and Topmed consent present, harmonized consent missing), and then evaluating the sub-rules to ensure the query is valid for both Topmed and clinical data access.

##### Harmonized Topmed Access Rule

The Harmonized Topmed Access Rule (`AR_TOPMED_<studyId>_<consentGroup>_HARMONIZED`) is used in Topmed privileges to allow access to both Topmed and harmonized data. It is configured as follows:

1. **Gates**:
   - **Harmonized Consent Gate**: Checks if the query includes harmonized consent (set to true for this rule)

2. **Sub-Rules**:
   - **Allowed Query Type Rules**: Ensure the query type is one of the allowed types
   - **Harmonized Sub-Rules**: Validate access to harmonized data
   - **Phenotype Sub-Rules**: Validate access to phenotypic data

This rule works by first checking if the harmonized consent gate passes, and then evaluating the sub-rules to ensure the query is valid for both Topmed and harmonized data access.

These complex rules with gates and sub-rules allow for sophisticated access control policies that can handle various combinations of data types and consent groups.

## Access Rule Evaluation

### Evaluation Flow

The evaluation of AccessRules begins in the `passesAccessRuleEvaluation` method of the `AuthorizationService` class. This method takes a request body object and a set of AccessRules as input and determines whether the request should be authorized.

#### Access Rule Evaluation Flow Diagram

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  JSON Query │────▶│ Collect All │────▶│ Pre-process │────▶│  Evaluate   │
│             │     │ Access Rules│     │ Access Rules│     │ Access Rules│
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                    │
                                                                    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Return     │◀────│ Determine   │◀────│ Evaluate    │◀────│ Evaluate    │
│  Result     │     │ Final Result│     │ Sub-Rules   │     │   Gates     │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

The evaluation flow follows these steps:

1. **Collection of AccessRules**: The system collects all AccessRules associated with the user's privileges for the requested application.
2. **Pre-processing**: AccessRules with the same JSONPath rule are merged to optimize evaluation.
3. **OR Evaluation**: AccessRules are evaluated with an OR relationship - if any rule passes, the request is authorized.
4. **Individual Rule Evaluation**: Each AccessRule is evaluated using the `evaluateAccessRule` method in `AccessRuleService`.
5. **Result Determination**: If any rule passes, the method returns true along with the name of the passing rule. If all rules fail, it returns false along with the list of failed rules.

### Individual AccessRule Evaluation

When evaluating an individual AccessRule using the `evaluateAccessRule` method, the following steps occur:

1. **Gate Evaluation**: If the AccessRule has gates, they are evaluated first:
   - If `gateAnyRelation` is false (default), all gates must pass (AND relationship)
   - If `gateAnyRelation` is true, at least one gate must pass (OR relationship)
   - If `evaluateOnlyByGates` is true, the result is determined solely by the gates

2. **Rule Extraction and Checking**: If gates pass (or there are no gates), the system:
   - Uses JSONPath to extract values from the request body based on the rule's expression
   - Evaluates the extracted value against the rule's criteria based on its type
   - If the main rule passes and there are sub-rules, evaluates all sub-rules

3. **Type-Based Evaluation**: Different evaluation strategies are used based on the AccessRule's type:
   - For string values: checks like CONTAINS, EQUALS, REGEX_MATCH
   - For collections: checks like ALL_CONTAINS, ANY_CONTAINS
   - For maps: can check keys, values, or both
   - Special types: IS_EMPTY, IS_NOT_EMPTY

### JSON Examples

Below are examples of how different JSON objects would be evaluated against various AccessRules:

#### Example 1: Simple Field Check

**AccessRule:**
```json
{
  "name": "FIELD_CHECK",
  "rule": "$.query.fields",
  "type": 5,
  "value": "\\specific_field\\"
}
```
*Note: type 5 represents ALL_CONTAINS*

**JSON Request (PASS):**
```json
{
  "query": {
    "fields": ["\\specific_field\\", "\\another_field\\"]
  }
}
```
*Why this passes: The rule type is ALL_CONTAINS (5) which checks if all elements in the collection contain the specified value. The JSONPath "\$.query.fields" extracts the array ["\\specific_field\\", "\\another_field\\"], and since "\\specific_field\\" is present in this array, the rule passes.*

**JSON Request (FAIL):**
```json
{
  "query": {
    "fields": ["\\different_field\\", "\\another_field\\"]
  }
}
```
*Why this fails: The rule type is ALL_CONTAINS (5) which checks if all elements in the collection contain the specified value. The JSONPath "\$.query.fields" extracts the array ["\\different_field\\", "\\another_field\\"], but "\\specific_field\\" is not present in this array, so the rule fails.*

#### Example 2: Nested Field Check with Gates

**AccessRule:**
```json
{
  "name": "COMPLEX_RULE",
  "evaluateOnlyByGates": true,
  "gates": [
    {
      "name": "GATE1",
      "rule": "$.query.type",
      "type": 4,
      "value": "COUNT"
    },
    {
      "name": "GATE2",
      "rule": "$.query.categoryFilters",
      "type": 14
    }
  ],
  "gateAnyRelation": false
}
```
*Notes:*
- *type 4 represents ALL_EQUALS*
- *type 14 represents IS_NOT_EMPTY*
- *gateAnyRelation: false means gates have an AND relationship*

**JSON Request (PASS):**
```json
{
  "query": {
    "type": "COUNT",
    "categoryFilters": {
      "\\consent\\": ["phs000123.c1"]
    }
  }
}
```
*Why this passes: This rule is evaluated only by its gates (evaluateOnlyByGates=true). The first gate (GATE1) checks if "\$.query.type" equals "COUNT", which it does. The second gate (GATE2) checks if "\$.query.categoryFilters" is not empty, which it isn't. Since both gates pass and they have an AND relationship (gateAnyRelation=false), the entire rule passes.*

**JSON Request (FAIL):**
```json
{
  "query": {
    "type": "RECORD",
    "categoryFilters": {
      "\\consent\\": ["phs000123.c1"]
    }
  }
}
```
*Why this fails: This rule is evaluated only by its gates. The first gate (GATE1) checks if "\$.query.type" equals "COUNT", but the value is "RECORD", so this gate fails. Even though the second gate (GATE2) passes because "\$.query.categoryFilters" is not empty, the gates have an AND relationship (gateAnyRelation=false), so all gates must pass. Since one gate fails, the entire rule fails.*

#### Example 3: Multiple AccessRules (OR Relationship)

When multiple AccessRules are evaluated, they have an OR relationship. The request passes if any rule passes.

**AccessRule 1:**
```json
{
  "name": "RULE1",
  "rule": "$.query.type",
  "type": 4,
  "value": "COUNT"
}
```
*Note: type 4 represents ALL_EQUALS*

**AccessRule 2:**
```json
{
  "name": "RULE2",
  "rule": "$.query.fields",
  "type": 5,
  "value": "\\allowed_field\\"
}
```
*Note: type 5 represents ALL_CONTAINS*

**JSON Request (PASS - Rule 1 passes):**
```json
{
  "query": {
    "type": "COUNT",
    "fields": ["\\different_field\\"]
  }
}
```
*Why this passes: When multiple rules are evaluated, they have an OR relationship. Rule 1 checks if "\$.query.type" equals "COUNT", which it does. Even though Rule 2 would fail (because "\\allowed_field\\" is not in the fields array), the request is authorized because at least one rule passes.*

**JSON Request (PASS - Rule 2 passes):**
```json
{
  "query": {
    "type": "RECORD",
    "fields": ["\\allowed_field\\", "\\another_field\\"]
  }
}
```
*Why this passes: Rule 1 fails because "\$.query.type" is "RECORD", not "COUNT". However, Rule 2 passes because "\$.query.fields" contains "\\allowed_field\\". Since at least one rule passes (OR relationship), the request is authorized.*

**JSON Request (FAIL - Neither rule passes):**
```json
{
  "query": {
    "type": "RECORD",
    "fields": ["\\different_field\\"]
  }
}
```
*Why this fails: Rule 1 fails because "\$.query.type" is "RECORD", not "COUNT". Rule 2 fails because "\$.query.fields" does not contain "\\allowed_field\\". Since no rules pass (and they have an OR relationship), the request is denied.*

### Understanding AccessRule Types

The `AccessRule.TypeNaming` class defines various types of evaluations:

- **NOT_CONTAINS (1)**: Checks if the value does not contain the specified string
- **NOT_CONTAINS_IGNORE_CASE (2)**: Case-insensitive version of NOT_CONTAINS
- **NOT_EQUALS (3)**: Checks if the value is not equal to the specified string
- **ALL_EQUALS (4)**: For collections, checks if all elements equal the specified value
- **ALL_CONTAINS (5)**: For collections, checks if all elements contain the specified value
- **ALL_CONTAINS_IGNORE_CASE (6)**: Case-insensitive version of ALL_CONTAINS
- **ANY_CONTAINS (7)**: For collections, checks if any element contains the specified value
- **NOT_EQUALS_IGNORE_CASE (8)**: Case-insensitive version of NOT_EQUALS
- **ALL_EQUALS_IGNORE_CASE (9)**: Case-insensitive version of ALL_EQUALS
- **ANY_EQUALS (10)**: For collections, checks if any element equals the specified value
- **ALL_REG_MATCH (11)**: For collections, checks if all elements match the specified regex
- **ANY_REG_MATCH (12)**: For collections, checks if any element matches the specified regex
- **IS_EMPTY (13)**: Checks if the value is empty
- **IS_NOT_EMPTY (14)**: Checks if the value is not empty
- **ALL_CONTAINS_OR_EMPTY (15)**: Passes if the collection is empty or all elements contain the value
- **ALL_CONTAINS_OR_EMPTY_IGNORE_CASE (16)**: Case-insensitive version of ALL_CONTAINS_OR_EMPTY

### Understanding Rule Pass/Fail Results

When a request is evaluated against access rules, the system determines which rules pass and which rules fail, and logs this information. Understanding these results is crucial for troubleshooting authorization issues.

#### How Pass/Fail Results Are Determined

1. **OR Relationship Between Rules**: When multiple access rules are evaluated, they have an OR relationship. If any rule passes, the request is authorized.

2. **Rule Evaluation Process**:
   - Each rule is evaluated in sequence
   - The first rule that passes causes the evaluation to stop and the request to be authorized
   - If a rule fails, it's added to a list of failed rules, and evaluation continues with the next rule
   - If all rules fail, the request is denied

3. **Logging of Results**: The system logs detailed information about which rules passed or failed:
   - If authorized: "passed by [rule_name]" is logged
   - If denied: "failed by rules: [rule1, rule2, ...]" is logged, listing all rules that failed

#### Common Reasons for Rule Failure

1. **JSONPath Extraction Failure**: The rule's JSONPath expression couldn't extract a value from the request body.

2. **Type Mismatch**: The extracted value doesn't match the expected type for the rule's evaluation strategy.

3. **Value Mismatch**: The extracted value doesn't satisfy the rule's criteria (e.g., doesn't contain or equal the specified value).

4. **Gate Failure**: For rules with gates, one or more gates failed:
   - For AND gates (gateAnyRelation=false): any gate failing causes the rule to fail
   - For OR gates (gateAnyRelation=true): all gates failing causes the rule to fail

5. **Sub-Rule Failure**: For rules with sub-rules, one or more sub-rules failed.

#### Troubleshooting Rule Evaluation

When troubleshooting authorization issues, consider:

1. **Which specific rule passed or failed**: Look at the rule's name, type, and value to understand what it was checking.

2. **For failed rules, why they failed**: Compare the rule's criteria with the request body to identify the mismatch.

3. **For rules with gates, which gate failed**: Gates are evaluated first, and their failure prevents the main rule from being evaluated.

4. **For complex rules with sub-rules, which sub-rule failed**: Sub-rules must all pass for the main rule to pass.

### Privilege Evaluation Against JSON Queries

This section explains how different types of privileges are evaluated against JSON query objects, focusing on genomic (Topmed) and phenotypic (Clinical) privileges, and how harmonized consent differs from non-harmonized consent.

#### Data Types and Privilege Creation

In the system, data types are categorized as:

- **G (Genomic)**: Refers to genomic data, typically from Topmed studies. Privileges for this data type are created using the `upsertTopmedPrivilege()` method.
- **P (Phenotypic)**: Refers to clinical/phenotypic data. Privileges for this data type are created using the `upsertClinicalPrivilege()` method.

A study can have one or both data types, and appropriate privileges are created based on the data types present.

#### Clinical Privilege Evaluation (upsertClinicalPrivilege)

Clinical privileges control access to phenotypic data. When a JSON query is evaluated against a clinical privilege:

1. **Query Template Matching**: The system checks if the query matches the privilege's query template, which includes:
   - The consent group concept path (different for harmonized vs. non-harmonized)
   - The study identifier and consent group

2. **Access Rule Evaluation**: The query is evaluated against the privilege's access rules:
   - **Parent Access Rule**: Checks if the query is accessing only the parent study data
   - **Topmed Parent Access Rule**: Ensures the query doesn't include genomic filters when accessing clinical data
   - **Harmonized Access Rule** (for harmonized studies only): Checks if the query is accessing harmonized data

##### JSON Example for Clinical Privilege (Non-Harmonized)

**Access Rule (Parent):**
```json
{
  "name": "AR_CONSENT_phs000123_c1_PARENT",
  "rule": "$.query.categoryFilters.\\_consents\\[*]",
  "type": 4,
  "value": "phs000123.c1"
}
```
*Note: type 4 represents ALL_EQUALS*

**JSON Query (PASS):**
```json
{
  "query": {
    "categoryFilters": {
      "\\_consents\\": ["phs000123.c1"]
    },
    "fields": ["\\_Parent Study Accession with Subject ID\\"],
    "expectedResultType": "COUNT"
  }
}
```
*Why this passes: The query is accessing only the parent study data (phs000123.c1) through the consent path "\\_consents\\", which matches the access rule.*

**JSON Query (FAIL):**
```json
{
  "query": {
    "categoryFilters": {
      "\\_consents\\": ["phs000123.c2"]
    },
    "fields": ["\\_Parent Study Accession with Subject ID\\"],
    "expectedResultType": "COUNT"
  }
}
```
*Why this fails: The query is trying to access a different consent group (c2) than the one allowed by the access rule (c1).*

#### Topmed Privilege Evaluation (upsertTopmedPrivilege)

Topmed privileges control access to genomic data. When a JSON query is evaluated against a Topmed privilege:

1. **Query Template Matching**: The system checks if the query matches the privilege's query template, which includes:
   - The Topmed consent group concept path
   - The study identifier and consent group

2. **Access Rule Evaluation**: The query is evaluated against the privilege's access rules:
   - **Topmed Access Rule**: Checks if the query is accessing only Topmed data
   - **Topmed Parent Access Rule** (if parent concept path exists): Allows access to both Topmed and parent clinical data
   - **Harmonized Topmed Access Rule** (if harmonized): Allows access to both Topmed and harmonized data

##### JSON Example for Topmed Privilege

**Access Rule (Topmed):**
```json
{
  "name": "AR_TOPMED_phs000123_c1",
  "rule": "$.query.categoryFilters.\\_topmed_consents\\[*]",
  "type": 4,
  "value": "phs000123.c1"
}
```
*Note: type 4 represents ALL_EQUALS*

**JSON Query (PASS):**
```json
{
  "query": {
    "categoryFilters": {
      "\\_topmed_consents\\": ["phs000123.c1"]
    },
    "fields": ["\\_Topmed Study Accession with Subject ID\\"],
    "expectedResultType": "COUNT",
    "variantInfoFilters": [
      {
        "categoryVariantInfoFilters": {
          "CHROM": ["1", "2"]
        }
      }
    ]
  }
}
```
*Why this passes: The query is accessing Topmed data for the correct consent group (phs000123.c1) and includes variant filters, which is allowed by the Topmed access rule.*

**JSON Query (FAIL):**
```json
{
  "query": {
    "categoryFilters": {
      "\\_topmed_consents\\": ["phs000456.c1"]
    },
    "fields": ["\\_Topmed Study Accession with Subject ID\\"],
    "expectedResultType": "COUNT",
    "variantInfoFilters": [
      {
        "categoryVariantInfoFilters": {
          "CHROM": ["1", "2"]
        }
      }
    ]
  }
}
```
*Why this fails: The query is trying to access a different study (phs000456) than the one allowed by the access rule (phs000123).*

#### Harmonized vs. Non-Harmonized Consent

Harmonized consent refers to data that has been standardized across multiple studies, allowing for cross-study analysis. The key differences in privilege evaluation are:

##### Non-Harmonized Consent:
- Uses the parent consent group concept path (`\\_consents\\`)
- Has access rules for parent data only
- Query scope is limited to the parent concept path

##### Harmonized Consent:
- Uses the harmonized consent group concept path (`\\_harmonized_consent\\`)
- Has additional access rules for harmonized data
- Query scope includes both parent and harmonized concept paths
- Allows queries that access harmonized data across multiple studies

##### JSON Example for Harmonized Consent

**Access Rule (Harmonized):**
```json
{
  "name": "AR_CONSENT_phs000123_c1_HARMONIZED",
  "rule": "$.query.categoryFilters.\\_harmonized_consent\\[*]",
  "type": 4,
  "value": "phs000123.c1"
}
```
*Note: type 4 represents ALL_EQUALS*

**JSON Query (PASS):**
```json
{
  "query": {
    "categoryFilters": {
      "\\_harmonized_consent\\": ["phs000123.c1"]
    },
    "fields": ["\\_Parent Study Accession with Subject ID\\", "\\_harmonized\\"],
    "expectedResultType": "COUNT"
  }
}
```
*Why this passes: The query is accessing harmonized data for the correct consent group (phs000123.c1) through the harmonized consent path "\\_harmonized_consent\\", which matches the access rule.*

**JSON Query (FAIL):**
```json
{
  "query": {
    "categoryFilters": {
      "\\_harmonized_consent\\": ["phs000123.c1"]
    },
    "fields": ["\\_Parent Study Accession with Subject ID\\", "\\_harmonized\\"],
    "expectedResultType": "COUNT",
    "variantInfoFilters": [
      {
        "categoryVariantInfoFilters": {
          "CHROM": ["1", "2"]
        }
      }
    ]
  }
}
```
*Why this fails: The query is trying to access harmonized data with variant filters, but the clinical harmonized access rule doesn't allow genomic filters. For this query to pass, the user would need a Topmed harmonized privilege.*

## Cross Consent Variables

### What are Cross Consent Variables?

Cross consent variables refer to data elements that span across multiple consent groups or studies. In the PIC-SURE authorization system, this functionality is primarily implemented through the harmonized consent mechanism, which allows researchers to perform cross-study analysis while maintaining appropriate access controls.

### How Cross Consent Variables are Implemented

The system implements cross consent variables through several key components:

1. **Different Consent Paths**: The system defines three different consent paths in `application.properties`:
   ```
   fence.harmonized.consent.group.concept.path=\\_harmonized_consent\\
   fence.parent.consent.group.concept.path=\\_consents\\
   fence.topmed.consent.group.concept.path=\\_topmed_consents\\
   ```

2. **Harmonized Concept Path**: A separate path for harmonized data:
   ```
   fence.consent.group.concept.path=\\DCC Harmonized data set\\
   ```

3. **Specialized Access Rules**: The system creates access rules that explicitly allow queries to include multiple consent groups in a single query.

### Harmonized Sub-Rules for Cross-Study Analysis

The `getHarmonizedSubRules()` method in `AccessRuleService` is central to enabling cross-consent functionality. As the code comment states:

```java
/**
 * Harmonized rules allow queries to include parent, harmonized, and topmed consent groups simultaneously.
 * 
 * This unified approach eliminates the need for separate rule combinations (like topmed+harmonized 
 * or parent+harmonized), enabling cross-study analysis while maintaining appropriate access controls.
 * The rules created by this method explicitly permit all three consent types in a single query,
 * allowing researchers to analyze data across multiple datasets with different consent structures.
 */
```

This method creates access rules that allow:
- Parent consent (`fence_parent_consent_group_concept_path`)
- Harmonized consent (`fence_harmonized_consent_group_concept_path`)
- Topmed consent (`fence_topmed_consent_group_concept_path`)

By allowing all three types of consent groups in a single query, researchers can perform cross-study analysis that spans multiple datasets.

### Technical Implementation Details

The implementation includes several key components:

1. **Privilege Creation**: When a role is created, the system determines if the study is harmonized and creates appropriate privileges:

```java
if (Boolean.TRUE.equals(isHarmonized)) {
    privs.add(upsertClinicalPrivilege(project_name, projectAlias, consent_group, concept_path, true));
}
```

2. **Query Scope Configuration**: Harmonized privileges have a broader query scope that includes both parent and harmonized concept paths:

```java
priv.setQueryScope(isHarmonized ? 
    String.format("[\"%s\",\"_\",\"%s\"]", conceptPath, fence_harmonized_concept_path) : 
    String.format("[\"%s\",\"_\"]", conceptPath));
```

3. **Access Rule Configuration**: Harmonized privileges have additional access rules that allow cross-consent queries:

```java
if (isHarmonized) {
    accessRules.add(createClinicalHarmonizedAccessRule(studyIdentifier, consent_group, conceptPath, projectAlias));
}
```

### Example JSON Query for Cross Consent Analysis

Below is an example of a JSON query that accesses data across multiple consent groups:

```json
{
  "query": {
    "categoryFilters": {
      "\\_harmonized_consent\\": ["phs000123.c1", "phs000456.c1"]
    },
    "fields": ["\\_Parent Study Accession with Subject ID\\"],
    "expectedResultType": "COUNT"
  }
}
```

This query accesses harmonized data from two different studies (phs000123.c1 and phs000456.c1) through the harmonized consent path. The system allows this because:

1. The user has harmonized privileges for both studies
2. The harmonized access rules allow access to multiple consent groups
3. The query scope includes the harmonized concept path

### Key Characteristics of Cross Consent Handling

1. **OR Relationship Between AccessRules**: When multiple access rules are evaluated, they have an OR relationship. If any rule passes, the request is authorized.

2. **Harmonized Sub-Rules**: Explicitly allow multiple consent groups in the same query.

3. **Broader Query Scope**: Harmonized privileges have a broader query scope that includes both parent and harmonized concept paths.

4. **Complex Gates and Sub-Rules**: Use complex combinations of gates and sub-rules to enforce sophisticated access control policies that can handle various combinations of data types and consent groups.

## Best Practices

1. **Role Naming Conventions**:
   - System roles: Use uppercase (e.g., "ADMIN")
   - Managed roles: Use prefix "MANAGED_" followed by study ID and consent group (e.g., "MANAGED_phs000123_c1")
   - Manual roles: Use prefix "MANUAL_ROLE_" followed by a descriptive name

2. **Privilege Naming Conventions**:
   - Use prefix "PRIV_" followed by the role name
   - For specific data types, add suffixes like "_HARMONIZED" or "_TOPMED"

3. **Access Rule Design**:
   - Keep rules simple and focused on a single condition when possible
   - Use gates for complex logical conditions
   - Document the purpose of each rule in its description

4. **Maintenance**:
   - Use the version field in roles to track changes
   - Update privileges when study metadata changes
   - Regularly review and clean up unused roles and privileges
