# ACEVision Basic Commands

This guide covers common ACEVision usage with NTLM authentication.

For Kerberos usage, see:

* [Kerberos Authentication](kerberos-authentication.md)

---

## Help Menu

Display available options:

```bash
acevision -h
```

or:

```bash
acevision --help
```

---

## Basic NTLM Enumeration

Run ACEVision against a domain controller using NTLM authentication.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10
```

---

## Resolve SIDs

Attempt to resolve SIDs into human-readable names.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --resolve-sids
```

Example output:

```text
SID: S-1-5-21-...
Resolved SID: management_svc
```

---

## Filter by SID

Analyze ACEs associated with a specific SID.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --filter-sid S-1-5-21-...
```

This is useful when investigating a specific user, group, service account, or computer account.

---

## Filter by SID and Show Only Escalation Rights

This is one of the most useful ACEVision workflows.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --resolve-sids \
    --filter-sid S-1-5-21-... \
    --only-escalation
```

`--only-escalation` displays escalation-relevant ACEs such as:

* WriteOwner
* WriteDACL
* GenericAll
* GenericWrite
* DCSync
* ForceChangePassword

`--hits-only` is an alias for `--only-escalation`.

---

## Analyze Multiple SIDs from a File

Use `--sid-file` to test multiple SIDs in one run.

Example `sids.txt`:

```text
S-1-5-21-...-1103
S-1-5-21-...-1104
S-1-5-21-...-1105
```

Run:

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --resolve-sids \
    --sid-file sids.txt \
    --only-escalation
```

The SID file can also contain simple `name,SID` pairs.

Example:

```text
judith.mader,S-1-5-21-...-1103
Management,S-1-5-21-...-1104
management_svc,S-1-5-21-...-1105
```

---

## Analyze a Specific LDAP Object

Use `--target-dn` to limit analysis to a specific LDAP distinguished name.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --target-dn "CN=Management,CN=Users,DC=domain,DC=htb"
```

---

## Check WriteOwner for a Specific Object

Use `--check-writeowner` when you want to quickly verify whether a SID has WriteOwner over a target object.

This requires both:

* `--filter-sid`
* `--target-dn`

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --target-dn "CN=Management,CN=Users,DC=domain,DC=htb" \
    --filter-sid S-1-5-21-... \
    --check-writeowner
```

---

## Limit the Number of Objects Processed

Use `--size-limit` for quicker testing or debugging.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --size-limit 100
```

---

## Use LDAPS

Use `--ldaps` to connect over LDAPS instead of LDAP.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --ldaps
```

---

## Use StartTLS

Use `--starttls` to negotiate StartTLS on LDAP.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --starttls
```

---

## Disable BloodHound Compatibility Inference

By default, ACEVision may infer some BloodHound-compatible GenericWrite-style relationships.

Disable this behavior with:

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --no-bh-compat
```

---

## Verbose Output

Use `--verbose` for additional debugging information.

```bash
acevision \
    --auth ntlm \
    -u user@domain.htb \
    -p 'Password123!' \
    -d domain.htb \
    --dc-ip 10.10.10.10 \
    --verbose
```

---

## Practical Workflow

A common workflow is:

```text
Find a SID
↓
Run ACEVision with --filter-sid
↓
Add --resolve-sids
↓
Add --only-escalation
↓
Review ACEs responsible for control relationships
```

Example:

```bash
acevision \
    --auth ntlm \
    -u judith.mader@certified.htb \
    -p judith09 \
    -d certified.htb \
    --dc-ip 10.129.231.186 \
    --resolve-sids \
    --filter-sid S-1-5-21-729746778-2675978091-3820388244-1103 \
    --only-escalation
```

---

## Related Guides

* [Finding SIDs](finding-sids.md)
* [Kerberos Authentication](kerberos-authentication.md)
* [Certified Case Study](../case-studies/certified.md)

