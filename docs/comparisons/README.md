# BloodHound vs ACEVision

## Overview

BloodHound and ACEVision serve different purposes.

BloodHound focuses on **relationship discovery**, while ACEVision focuses on **relationship interpretation**.

### BloodHound

BloodHound answers:

- What relationship exists?
- Which object controls another object?
- What attack path is possible?

### ACEVision

ACEVision answers:

- Why does this relationship matter?
- What should be done next?
- Which DACL modification is recommended?
- What abuse path is available?
- What is the potential impact?
- What is the expected attack flow?

---

## Comparison Philosophy

> BloodHound shows the relationship.
>
> ACEVision explains the relationship.

---

## Included Comparisons

### WriteOwner → Group

**BloodHound**

- Identifies a WriteOwner relationship.

**ACEVision**

- Detects the target object type (Group).
- Recommends `WriteMembers`.
- Explains the abuse path.
- Provides expected outcomes.

---

### WriteDACL → Domain

**BloodHound**

- Identifies a WriteDACL relationship over the domain.

**ACEVision**

- Identifies the target object type (Domain).
- Recommends DCSync rights.
- Explains why the recommendation is appropriate.
- Provides impact assessment and attack flow guidance.

---

### DCSync → Domain

**BloodHound**

- Identifies replication rights.

**ACEVision**

- Detects DCSync-capable permissions.
- Provides impact assessment.
- Explains potential outcomes.
- Maps the relationship to an actionable attack path.

---

## Purpose

These screenshots are not intended to compare tools competitively.

BloodHound remains one of the most valuable Active Directory analysis platforms available.

The purpose of these comparisons is to demonstrate how ACEVision can complement BloodHound by adding context, recommendations, and attack-flow guidance to identified relationships.

---

## Current Advisor Validation Coverage

| Right | Object Type | Status |
|---------|---------|---------|
| WriteOwner | User | ✅ |
| WriteOwner | Group | ✅ |
| GenericAll | User | ✅ |
| GenericWrite | User | ✅ |
| ForceChangePassword | User | ✅ |
| DCSync | Domain | ✅ |
| WriteDACL | Domain | ✅ |
