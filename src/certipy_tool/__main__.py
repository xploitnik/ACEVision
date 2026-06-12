# acevision/__main__.py
# -*- coding: utf-8 -*-
#
# CLI entry for ACEVision.
# Supports NTLM and Kerberos (GSSAPI) binds.
#
import sys
import argparse
from typing import List

from .auth import LDAPSocket
from .parse_acl import (
    parse_acl_entries,
    enumerate_acls_for_sid,
    check_writeowner_for_dn,
)

BANNER = """\
[ACEVision] Active Directory ACE and ACL visibility framework
"""


def load_sids_from_file(path: str) -> List[str]:
    sids = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "," in line:
                    parts = [p.strip() for p in line.split(",") if p.strip()]
                    sid_candidate = parts[-1]
                else:
                    sid_candidate = line

                if sid_candidate.upper().startswith("S-1-"):
                    sids.append(sid_candidate)
                else:
                    for tok in line.split():
                        if tok.upper().startswith("S-1-"):
                            sids.append(tok)
                            break

        return sids

    except Exception as e:
        raise RuntimeError(f"Failed to read SID file {path}: {e}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ACEVision — Enumerate Active Directory ACEs and ACLs through LDAP",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("--auth", choices=["ntlm", "kerberos"], default="ntlm")
    p.add_argument("-u", "--username", help="User. Required for NTLM.")
    p.add_argument("-p", "--password", help="Password. Required for NTLM.")
    p.add_argument("-d", "--domain", required=True, help="Domain FQDN.")
    p.add_argument("--dc-ip", required=True, help="DC IP to query.")
    p.add_argument("--dc-host", help="DC FQDN. Recommended for Kerberos.")
    p.add_argument("--ccache", help="Path to Kerberos ccache.")

    p.add_argument("--filter-sid", help="SID to filter.")
    p.add_argument("--sid-file", help="Path to file with SIDs.")
    p.add_argument("--target-dn", help="Base/target DN to limit subtree.")

    p.add_argument("--size-limit", type=int, default=0)
    p.add_argument("--check-writeowner", action="store_true")

    p.add_argument("--only-escalation", dest="only_escalation", action="store_true")
    p.add_argument("--hits-only", dest="only_escalation", action="store_true")
    p.add_argument("--resolve-sids", action="store_true")
    p.add_argument("--ldaps", action="store_true")
    p.add_argument("--starttls", action="store_true")
    p.add_argument("--no-bh-compat", dest="bh_compat", action="store_false")
    p.add_argument("--verbose", action="store_true")

    p.set_defaults(bh_compat=True)
    return p


def main() -> int:
    print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        print(f"[INFO] DC: {args.dc_ip}")
        print(f"[INFO] Domain: {args.domain}")

        if args.dc_host:
            print(f"[INFO] DC Host (FQDN): {args.dc_host}")

        if args.target_dn:
            print(f"[INFO] Target DN: {args.target_dn}")

        if args.filter_sid:
            print(f"[INFO] Filter SID: {args.filter_sid}")

        if args.sid_file:
            print(f"[INFO] SID file: {args.sid_file}")

        print(f"[INFO] Auth method: {args.auth}")

    target_host = (
        args.dc_ip
        if args.auth == "ntlm"
        else (args.dc_host or f"dc.{args.domain}")
    )

    try:
        print("[AUTH] Binding to LDAP...")

        if args.auth == "ntlm":
            if not args.username or not args.password:
                print("[ERROR] NTLM requires -u/--username and -p/--password.")
                return 2

        sock = LDAPSocket(
            target=target_host,
            username=args.username or "",
            password=args.password or "",
            domain=args.domain,
            dc_ip=args.dc_ip,
            use_ldaps=args.ldaps,
            auth_method=args.auth,
            ccache=args.ccache,
            dc_fqdn=args.dc_host or None,
            starttls=args.starttls,
        )

        print("[AUTH] LDAP bind successful.")

    except Exception as e:
        print(f"[ERROR] LDAP bind failed: {e}")
        return 1

    resolver = None
    resolver_details = None

    if args.resolve_sids:
        maybe = getattr(sock, "resolve_sid", None)
        maybe_details = getattr(sock, "resolve_sid_details", None)

        if callable(maybe):
            resolver = maybe
        elif args.verbose:
            print("[WARN] resolve_sid() not available; SIDs will be shown raw.")

        if callable(maybe_details):
            resolver_details = maybe_details
        elif args.verbose:
            print("[WARN] resolve_sid_details() not available; principal types will be unresolved.")

    if args.check_writeowner:
        if not args.filter_sid or not args.target_dn:
            print("[ERROR] --check-writeowner requires --filter-sid and --target-dn.")
            return 2

        ok = check_writeowner_for_dn(
            sock,
            args.target_dn,
            args.filter_sid,
        )

        return 0 if ok else 3

    try:
        if args.size_limit and args.size_limit > 0:
            entries = sock.get_effective_control_entries()

            if args.target_dn:
                base_l = args.target_dn.lower()

                entries = [
                    entry
                    for entry in entries
                    if entry[0].lower() == base_l
                    or entry[0].lower().endswith("," + base_l)
                ]

            entries = entries[: args.size_limit]

            if args.verbose:
                print(f"[INFO] Objects to process (limit): {len(entries)}")

            parse_acl_entries(
                entries,
                filter_sid=args.filter_sid,
                resolve_sid=resolver,
                resolve_sid_details=resolver_details,
                only_escalation=args.only_escalation,
                bh_compat=args.bh_compat,
                verbose=args.verbose,
            )

        else:
            if args.sid_file:
                try:
                    sids = load_sids_from_file(args.sid_file)
                except Exception as e:
                    print(f"[ERROR] Could not load SID file: {e}")
                    return 6

                if not sids:
                    print(f"[WARN] No valid SIDs found in {args.sid_file}")
                else:
                    for sid in sids:
                        print("\n" + "=" * 60)
                        print(f"[SID-TEST] Enumerating ACLs for SID: {sid}")
                        print("=" * 60)

                        try:
                            enumerate_acls_for_sid(
                                sock=sock,
                                filter_sid=sid,
                                target_dn=args.target_dn,
                                resolve_sid=resolver,
                                resolve_sid_details=resolver_details,
                                only_escalation=args.only_escalation,
                                bh_compat=args.bh_compat,
                                verbose=args.verbose,
                            )

                        except Exception as e:
                            print(f"[ERROR] Enumeration failed for {sid}: {e}")

            else:
                enumerate_acls_for_sid(
                    sock=sock,
                    filter_sid=args.filter_sid,
                    target_dn=args.target_dn,
                    resolve_sid=resolver,
                    resolve_sid_details=resolver_details,
                    only_escalation=args.only_escalation,
                    bh_compat=args.bh_compat,
                    verbose=args.verbose,
                )

    except Exception as e:
        print(f"[ERROR] Enumeration failed: {e}")
        return 5

    return 0


if __name__ == "__main__":
    sys.exit(main())
