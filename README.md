## ACEVision
Active Directory control relationship auditing and ACL visibility framework.


<img width="650" height="302" alt="image" src="https://github.com/user-attachments/assets/9701f596-bd91-438a-9aaa-43d1292a5b0d" />


ACEVision is an Active Directory auditing tool focused on exposing effective control relationships directly from LDAP security descriptors.

Rather than abstracting privilege escalation into simplified attack paths, ControlMap helps operators, defenders, and students understand why a relationship exists by exposing the underlying ACEs, SIDs, ownership relationships, and effective rights that grant control over AD objects.

---

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















