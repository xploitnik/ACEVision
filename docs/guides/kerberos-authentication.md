# Kerberos Authentication

ACEVision supports Kerberos authentication through the `--auth kerberos` option.

This guide demonstrates a typical Kerberos workflow using a cached TGT.

---

# Why Kerberos?

Some environments restrict or disable NTLM authentication.

In these situations, Kerberos may be the only supported authentication method.

ACEVision can authenticate using an existing Kerberos ticket stored in a credential cache (`ccache`).

---

# Step 1 — Obtain a TGT

Use Impacket to request a Ticket Granting Ticket (TGT).

```bash
impacket-getTGT domain.htb/user:'Password123!'
```

Example:

```bash
impacket-getTGT certified.htb/judith.mader:'judith09'
```

A `.ccache` file will be generated.

Example:

```text
judith.mader.ccache
```

---

# Step 2 — Export KRB5CCNAME

Point Kerberos tools to the cache.

```bash
export KRB5CCNAME=judith.mader.ccache
```

Verify:

```bash
echo $KRB5CCNAME
```

Expected output:

```text
judith.mader.ccache
```

---

# Step 3 — Verify the Ticket

Check the contents of the cache.

```bash
klist
```

Example output:

```text
Default principal: judith.mader@CERTIFIED.HTB

krbtgt/CERTIFIED.HTB@CERTIFIED.HTB
```

If no ticket appears, request a new TGT.

---

# Step 4 — Configure DNS and Hosts

Kerberos relies heavily on hostnames.

Ensure the Domain Controller hostname resolves correctly.

Example:

```text
10.129.231.186 DC01.certified.htb
```

Verify:

```bash
getent hosts DC01.certified.htb
```

---

# Step 5 — Verify the LDAP SPN

Confirm the LDAP Service Principal Name can be requested.

```bash
kvno ldap/DC01.certified.htb
```

Expected result:

```text
ldap/DC01.certified.htb
```

This confirms Kerberos can obtain a service ticket for LDAP.

---

# Step 6 — Run ACEVision

Basic Kerberos authentication:

```bash
acevision \
    --auth kerberos \
    -d certified.htb \
    --dc-ip 10.129.231.186 \
    --dc-host DC01.certified.htb
```

---

# Kerberos with SID Filtering

Example:

```bash
acevision \
    --auth kerberos \
    -d certified.htb \
    --dc-ip 10.129.231.186 \
    --dc-host DC01.certified.htb \
    --resolve-sids \
    --filter-sid S-1-5-21-729746778-2675978091-3820388244-1104 \
    --only-escalation
```

---

# Using a Specific Cache

If multiple caches exist:

```bash
acevision \
    --auth kerberos \
    -d certified.htb \
    --dc-ip 10.129.231.186 \
    --dc-host DC01.certified.htb \
    --ccache judith.mader.ccache
```

---

# Common Errors

## Cannot Contact KDC

Check:

```bash
getent hosts DC01.certified.htb
```

Verify DNS and `/etc/hosts`.

---

## No Credentials Cache Found

Check:

```bash
echo $KRB5CCNAME
```

and:

```bash
klist
```

---

## Server Not Found in Kerberos Database

Verify the Domain Controller FQDN:

```bash
kvno ldap/DC01.certified.htb
```

The hostname must match the LDAP SPN.

---

## Clock Skew Too Great

Check local time:

```bash
date
```

Kerberos is sensitive to time differences between client and server.

---

# Kerberos-Only Workflow

A common workflow is:

```text
Get TGT
↓
Export KRB5CCNAME
↓
Verify Ticket with klist
↓
Verify LDAP SPN with kvno
↓
Run ACEVision with --auth kerberos
```

---

# Related Guides

* [Basic Commands](basic-commands.md)
* [Finding SIDs](finding-sids.md)
* [Certified Case Study](../case-studies/certified.md)

