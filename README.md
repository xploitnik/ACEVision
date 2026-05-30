## ACEVision
ACEVision reveals the exact ACE granting control in Active Directory.

Instead of only displaying attack paths, ACEVision parses live LDAP security descriptors to identify the exact permissions responsible for object control.

<img width="650" height="302" alt="image" src="https://github.com/user-attachments/assets/9701f596-bd91-438a-9aaa-43d1292a5b0d" />

Rather than reducing privilege escalation to graph edges and attack paths, ACEVision helps operators, defenders, and students understand why a relationship exists by exposing the underlying ACEs, SIDs, ownership relationships, and effective rights that grant control over Active Directory objects.

---

## Quick Start

Clone the repository and install the dependencies:

```bash
git clone https://github.com/xploitnik/ACEVision.git
cd ACEVision
pip install .
acevision

```

Filter results to a specific SID:

```bash
acevision \
  --auth ntlm \
  -u ryan \
  -p 'Password123!' \
  -d sequel.htb \
  --dc-ip 10.129.242.173 \
  --filter-sid S-1-5-21-...
```

For additional examples and advanced usage, see:

- docs/usage/basic-commands.md
- docs/usage/kerberos-authentication.md
- docs/case-studies/

  
## Philosophy

Modern Active Directory tooling often prioritizes automated exploitation or high-level graph relationships.

ACEVision focuses on visibility and understanding.

The goal is to help answer questions like:

* Who effectively controls this object?
* Which ACE grants that control?
* Which SID owns the object?
* Why does BloodHound show this escalation path?
* Which permissions allow privilege escalation?
* How do LDAP security descriptors translate into real-world control?

---

## Features

* Enumerate LDAP security descriptors
* Parse DACL ACE entries
* Resolve SIDs to human-readable identities
* Audit effective control relationships
* Detect escalation-relevant permissions:

  * GenericAll
  * GenericWrite
  * WriteOwner
  * WriteDACL
* Analyze Active Directory object ownership
* Audit AD CS template permissions
* Filter ACEs by SID or target object
* Educational-friendly ACE visibility
* BloodHound relationship validation

---



## Why ACEVision?

Many AD tools simplify privilege escalation into graph edges or attack paths.

ACEVision exposes the raw access control relationships underneath those paths.

Instead of only showing:

```text
UserA → GenericAll → UserB
```

ACEVision focuses on showing:

* The actual ACE
* The actual SID
* The actual LDAP object
* The actual access mask
* The actual permission granting control

This makes the tool useful for:

* Active Directory auditing
* Security research
* Red team analysis
* Blue team validation
* Educational demonstrations
* ACL troubleshooting















