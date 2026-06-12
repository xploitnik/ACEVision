# certipy_tool/auth.py
# -*- coding: utf-8 -*-
#
# LDAP socket for ACEVision
#
from typing import Optional
import os

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, SASL, GSSAPI
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID


def domain_to_base_dn(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    return ",".join(f"DC={p}" for p in parts)


def classify_ldap_object_type(object_classes, dn: str = "") -> str:
    classes = [str(c).lower() for c in (object_classes or [])]
    dn_l = (dn or "").lower()

    if "domaindns" in classes:
        return "Domain Object"

    if "grouppolicycontainer" in classes:
        return "GPO Object"

    if "pkicertificatetemplate" in classes:
        return "Certificate Template Object"

    if "organizationalunit" in classes:
        return "OU Object"

    # Computer includes "user", so computer must come before user.
    if "computer" in classes:
        return "Computer Object"

    if "group" in classes:
        return "Group Object"

    if "user" in classes:
        return "User Object"

    if dn_l.startswith("dc=") and all(part.strip().startswith("dc=") for part in dn_l.split(",")):
        return "Domain Object"

    # Generic fallback for normal account objects when objectClass parsing fails.
    if dn_l.startswith("cn=") and "dc=" in dn_l:
        return "User Object"

    return "Unresolved"


class LDAPSocket:
    def __init__(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
        dc_ip: str,
        use_ldaps: bool = False,
        auth_method: str = "ntlm",
        ccache: Optional[str] = None,
        dc_fqdn: Optional[str] = None,
        starttls: bool = False,
        network_timeout: int = 10,
        disable_referrals: bool = True,
    ):
        self.target = target
        self.username = username or ""
        self.password = password or ""
        self.domain = domain
        self.dc_ip = dc_ip
        self.use_ldaps = use_ldaps
        self.auth_method = (auth_method or "ntlm").lower().strip()
        self.ccache = ccache
        self.dc_fqdn = dc_fqdn
        self.starttls = starttls
        self.network_timeout = network_timeout
        self.disable_referrals = disable_referrals

        ldap_host = self.dc_fqdn or self.target

        server = Server(
            ldap_host,
            use_ssl=self.use_ldaps,
            get_info=ALL,
            connect_timeout=self.network_timeout,
        )

        if self.auth_method == "kerberos":
            if self.ccache:
                os.environ["KRB5CCNAME"] = self.ccache

            self.conn = Connection(
                server,
                authentication=SASL,
                sasl_mechanism=GSSAPI,
                auto_bind=False,
                read_only=True,
            )

            if not self.use_ldaps and self.starttls:
                self.conn.open()
                self.conn.start_tls()

            if not self.conn.bind():
                raise RuntimeError(
                    f"[AUTH] Kerberos (GSSAPI) bind failed: {self.conn.last_error}"
                )

            print("[AUTH] LDAP Kerberos (GSSAPI) bind successful.")

        elif self.auth_method == "ntlm":
            user_part = self.username.split("@", 1)[0]
            ntlm_user = f"{self.domain.split('.')[0].upper()}\\{user_part}"

            self.conn = Connection(
                server,
                user=ntlm_user,
                password=self.password,
                authentication=NTLM,
                auto_bind=False,
                read_only=True,
            )

            if not self.use_ldaps and self.starttls:
                self.conn.open()
                self.conn.start_tls()

            if not self.conn.bind():
                raise RuntimeError(
                    f"[AUTH] NTLM/simple bind failed: {self.conn.last_error}"
                )

            print("[AUTH] LDAP bind successful (NTLM).")

        else:
            raise ValueError(f"Unsupported auth method: {self.auth_method}")

        self.base_dn = domain_to_base_dn(self.domain)

        try:
            if self.disable_referrals and hasattr(self.conn, "strategy"):
                self.conn.strategy.referrals = False
        except Exception:
            pass

    def get_effective_control_entries(self):
        controls = security_descriptor_control(sdflags=0x04)
        who = self.username or "kerberos"

        print(f"[AUTH] Searching objects with ACLs for {who}@{self.domain}...")

        self.conn.search(
            search_base=self.base_dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=["nTSecurityDescriptor", "objectClass"],
            controls=controls,
        )

        entries = []

        for entry in self.conn.entries:
            try:
                raw_sd = entry["nTSecurityDescriptor"].raw_values[0]
                sd = SR_SECURITY_DESCRIPTOR(raw_sd)

                try:
                    object_classes = [str(c) for c in entry["objectClass"].values]
                except Exception:
                    try:
                        object_classes = [str(c) for c in entry.objectClass.values]
                    except Exception:
                        object_classes = []

                entries.append((entry.entry_dn, sd, object_classes))
            except Exception:
                continue

        return entries

    def _sid_to_ldap_filter(self, sid_str: str) -> str:
        sid_obj = LDAP_SID()
        sid_obj.fromCanonical(sid_str)
        sid_bytes = sid_obj.getData()
        hex_esc = "".join("\\{:02x}".format(b) for b in sid_bytes)
        return f"(objectSid={hex_esc})"

    def resolve_sid(self, sid_str: str) -> str:
        """
        Backward-compatible SID resolver.
        Returns only a display name.
        """
        details = self.resolve_sid_details(sid_str)
        return details.get("name") or sid_str

    def resolve_sid_details(self, sid_str: str) -> dict:
        """
        LDAP-enriched SID resolver.

        Returns:
          {
            "sid": "...",
            "name": "backup",
            "dn": "CN=backup,OU=Administrator,DC=spookysec,DC=local",
            "object_classes": ["top", "person", "organizationalPerson", "user"],
            "object_type": "User Object"
          }
        """
        details = {
            "sid": sid_str,
            "name": sid_str,
            "dn": "",
            "object_classes": [],
            "object_type": "Unresolved",
        }

        try:
            flt = self._sid_to_ldap_filter(sid_str)

            self.conn.search(
                search_base=self.base_dn,
                search_filter=flt,
                search_scope=SUBTREE,
                attributes=[
                    "sAMAccountName",
                    "cn",
                    "distinguishedName",
                    "objectClass",
                ],
            )

            if not self.conn.entries:
                return details

            e = self.conn.entries[0]

            try:
                sam = str(e["sAMAccountName"])
                if sam and sam.lower() != "none":
                    details["name"] = sam
            except Exception:
                pass

            if details["name"] == sid_str:
                try:
                    cn = str(e["cn"])
                    if cn and cn.lower() != "none":
                        details["name"] = cn
                except Exception:
                    pass

            try:
                dn = str(e["distinguishedName"])
                if dn and dn.lower() != "none":
                    details["dn"] = dn
            except Exception:
                try:
                    details["dn"] = str(e.entry_dn)
                except Exception:
                    details["dn"] = ""

            try:
                details["object_classes"] = [str(c) for c in e["objectClass"].values]
            except Exception:
                try:
                    details["object_classes"] = [str(c) for c in e.objectClass.values]
                except Exception:
                    details["object_classes"] = []

            details["object_type"] = classify_ldap_object_type(
                details["object_classes"],
                details["dn"],
            )

            return details

        except Exception:
            return details
