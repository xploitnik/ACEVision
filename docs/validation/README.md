# ACEVision Advisor Validation

This directory contains validation screenshots used to verify ACEVision Advisor recommendations against real-world Active Directory privilege escalation paths.

The objective of these validations is to confirm that ACEVision Advisor correctly identifies the triggering right, understands the target object type, and recommends an appropriate abuse path or DACL modification.

## Validation Methodology

Each validation was performed against real Active Directory environments and compared against known privilege escalation techniques and BloodHound relationships.

ACEVision Advisor evaluates:

- Object Type
- Trigger Right
- Recommended DACL
- Recommended Abuse Path
- Potential Outcomes
- Suggested Flow

## Validated Rights

| Right | Object Type | Status |
|---------|---------|---------|
| WriteOwner | User | ✅ Validated |
| WriteOwner | Group | ✅ Validated |
| GenericAll | User | ✅ Validated |
| GenericWrite | User | ✅ Validated |
| ForceChangePassword | User | ✅ Validated |
| DCSync | Domain | ✅ Validated |
| WriteDACL | Domain | ✅ Validated |

## Comparison Evidence

Additional BloodHound vs ACEVision comparison screenshots are available under:

```text
docs/comparisons/
```

These comparisons demonstrate the difference between relationship discovery and relationship interpretation.

> BloodHound shows the relationship.
>
> ACEVision explains the relationship.

## Future Validation Targets

The following advisor paths remain candidates for additional validation:

- WriteOwner → Domain
- WriteDACL → User
- WriteDACL → Group
- GenericAll → Group
- GenericAll → Computer
- GenericWrite → Computer
