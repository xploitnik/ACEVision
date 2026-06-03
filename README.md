
# ACEVision

Active Directory control relationship auditing and ACL visibility framework.

ACEVision reveals the exact ACE granting control in Active Directory and explains what that control means.

Instead of only displaying attack paths, ACEVision parses live LDAP security descriptors to identify:

- Object Type
- Trigger Right
- Effective Permissions
- Recommended DACL Modifications
- Recommended Abuse Paths
- Potential Outcomes
- Suggested Attack Flows

---

![ACEVision Hero](docs/images/hero/hero_dcsync.png)

---

## ACEVision Advisor

ACEVision Advisor transforms raw ACL data into actionable Active Directory context.

Given an ACE, ACEVision can:

- Detect the target object type
- Identify the escalation-triggering permission
- Recommend the next DACL modification
- Recommend an abuse path
- Estimate impact and confidence
- Explain the expected attack flow

### Advisor Workflow

```text
Object Type
     ↓
Trigger Right
     ↓
ACEVision Advisor
     ↓
Recommended DACL
     ↓
Potential Outcomes
     ↓
Suggested Flow
```

Rather than reducing privilege escalation to graph edges and attack paths, ACEVision helps operators, defenders, and students understand why a relationship exists by exposing the underlying ACEs, SIDs, ownership relationships, and effective rights that grant control over Active Directory objects.

---

## Validation Framework

ACEVision Advisor recommendations have been validated against real Active Directory privilege escalation paths.

### Currently Validated

| Right | Object Type | Status |
|---------|---------|---------|
| WriteOwner | User | ✅ |
| WriteOwner | Group | ✅ |
| GenericAll | User | ✅ |
| GenericWrite | User | ✅ |
| ForceChangePassword | User | ✅ |
| DCSync | Domain | ✅ |
| WriteDACL | Domain | ✅ |

Validation screenshots are available under:

```text
docs/validation/
```

---

## BloodHound Comparisons

BloodHound and ACEVision serve different purposes.

### BloodHound

Answers:

- What relationship exists?
- Which object controls another object?
- Which attack path is possible?

### ACEVision

Answers:

- Why does this relationship matter?
- What should happen next?
- Which DACL modification is recommended?
- Which abuse path is available?
- What is the expected outcome?

> BloodHound shows the relationship.
>
> ACEVision explains the relationship.

Comparison screenshots are available under:

```text
docs/comparisons/
```

---

## Documentation

### Guides

- [Basic Commands](docs/guides/basic-commands.md)
- [Finding SIDs](docs/guides/finding-sids.md)
- [Kerberos Authentication](docs/guides/kerberos-authentication.md)

### Research

- [HTB Certified Case Study](docs/case-studies/certified.md)

### Validation

- [ACEVision Advisor Validation](docs/validation/README.md)

### Comparisons

- [BloodHound vs ACEVision](docs/comparisons/README.md)

---

## Quick Start

Clone the repository and install the dependencies:

```bash
git clone https://github.com/xploitnik/ACEVision.git

cd ACEVision

pip install -e .
```

Example:

```bash
acevision \
    --auth ntlm \
    -u ryan \
    -p 'Password123!' \
    -d sequel.htb \
    --dc-ip 10.129.242.173 \
    --filter-sid S-1-5-21-...
```

---

## Features

- Enumerate LDAP security descriptors
- Parse DACL ACE entries
- Resolve SIDs to identities
- Object Type Detection
- Trigger Right Detection
- ACEVision Advisor
- Recommended DACL Generation
- Abuse Path Recommendations
- Confidence Assessment
- Impact Assessment
- Suggested Attack Flows
- Effective Control Analysis
- BloodHound Relationship Validation
- NTLM Authentication
- Kerberos Authentication
- AD CS ACL Analysis

---

## Philosophy

Modern Active Directory tooling often prioritizes attack paths.

ACEVision focuses on understanding the permissions that create those paths.

The goal is to answer questions such as:

- Who actually controls this object?
- Which ACE grants that control?
- Why does BloodHound show this edge?
- Which permission is responsible?
- What is the next logical escalation step?

ACEVision encourages a SID-centric investigation workflow that allows operators to analyze control relationships throughout Active Directory without first compromising every account in the chain.

---

## License

Released under the MIT License.
