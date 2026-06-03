# certipy_tool/auth.py
# -*- coding: utf-8 -*-
#
# LDAP socket for ACEVision:
#  - NTLM simple bind (DOMAIN\user) on ldap:// or ldaps://
#  - Kerberos SASL/GSSAPI bind using the caller's ccache (kinit / KRB5CCNAME)
#  - get_effective_control_entries(): returns [(dn, SR_SECURITY_DESCRIPTOR)]
#  - resolve_sid(sid): tries to resolve SIDs to names by searching objectSid (binary)
#
from typing import List, Tuple, Optional
import os

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, SASL, GSSAPI
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID


def domain_to_base_dn(domain: str) -> str:
    # "certified.htb" -> "DC=certified,DC=htb"
    parts = [p for p in domain.split(".") if p]
    return ",".join(f"DC={p}" for p in parts)


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
        """
        ACEVision LDAP wrapper.

        Supports:
        - NTLM authentication
        - Kerberos authentication through SASL/GSSAPI
        - LDAP, LDAPS, and optional StartTLS
        - Security descriptor retrieval
        - SID resolution

        target: host/IP or FQDN to connect to
        username/password: used for NTLM only
        domain: domain FQDN, e.g. certified.htb
        auth_method: "ntlm" or "kerberos"
        ccache: optional Kerberos ccache path
        dc_fqdn: preferred FQDN for Kerberos SPN ldap/<fqdn>
        starttls: negotiate StartTLS on LDAP 389 if not using LDAPS
        """
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
        """
        Return a list of (DN, SR_SECURITY_DESCRIPTOR, object_classes) for the domain subtree.
        Only requests the DACL (sdflags=0x04) plus objectClass for ACEVision Advisor.
        """
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
                object_classes = []

                try:
                    object_classes = list(entry["objectClass"].values)
                except Exception:
                    object_classes = []

                entries.append((entry.entry_dn, sd, object_classes))
            except Exception:
                continue

        return entries

    def resolve_sid(self, sid_str: str) -> str:
        """
        Try to resolve a SID to sAMAccountName/CN by searching objectSid binary.
        Returns original SID string on failure.
        """
        try:
            sid_obj = LDAP_SID()
            sid_obj.fromCanonical(sid_str)
            sid_bytes = sid_obj.getData()

            hex_esc = "".join("\\{:02x}".format(b) for b in sid_bytes)
            flt = f"(objectSid={hex_esc})"

            self.conn.search(
                search_base=self.base_dn,
                search_filter=flt,
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "cn", "distinguishedName"],
            )

            if not self.conn.entries:
                return sid_str

            e = self.conn.entries[0]

            for attr in ("sAMAccountName", "cn", "distinguishedName"):
                try:
                    val = str(e[attr])
                    if val:
                        return val
                except Exception:
                    continue

            return sid_str

        except Exception:
            return sid_str




