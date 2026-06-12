# -*- coding: utf-8 -*-
#
# ACEVision - Active Directory ACE analysis engine
#
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
import time
import uuid

try:
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
except Exception:
    SR_SECURITY_DESCRIPTOR = object

# === DS rights ===
DS_RIGHTS = {
    0x00000001: "CreateChild",
    0x00000002: "DeleteChild",
    0x00000004: "ListChildren",
    0x00000008: "Self",
    0x00000010: "ReadProperty",
    0x00000020: "WriteProperty",
    0x00000040: "DeleteTree",
    0x00000080: "ListObject",
    0x00000100: "ControlAccess",
}

# === Standard rights ===
STANDARD_RIGHTS = {
    0x00010000: "Delete",
    0x00020000: "ReadControl",
    0x00040000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00100000: "Synchronize",
    0x01000000: "AccessSystemSecurity",
}

# === Generic rights ===
GENERIC_RIGHTS = {
    0x10000000: "GenericAll",
    0x20000000: "GenericExecute",
    0x40000000: "GenericWrite",
    0x80000000: "GenericRead",
}

RIGHTS = {**DS_RIGHTS, **STANDARD_RIGHTS, **GENERIC_RIGHTS}

ALL_RIGHTS_MASK = 0
for bit in RIGHTS:
    ALL_RIGHTS_MASK |= bit

ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x05: "ACCESS_ALLOWED_OBJECT",
    0x06: "ACCESS_DENIED_OBJECT",
    0x07: "SYSTEM_AUDIT_OBJECT",
    0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
    0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
    0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT",
}

SE_DACL_PRESENT = 0x0004

OBJECT_ACE_TYPES = {0x05, 0x06, 0x07, 0x0B, 0x0C, 0x0F}

ACE_OBJECT_TYPE_PRESENT = 0x01
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02

EXTENDED_RIGHTS_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
}

CRITICAL_DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",
}

FORCE_CHANGE_PASSWORD_GUIDS = {
    "00299570-246d-11d0-a768-00aa006e0529",
}

FRIENDLY_OBJECT_TYPE_LABELS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DCSync",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DCSync",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DCSync-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
}


def _ace_type_name(t: int) -> str:
    return ACE_TYPE_NAMES.get(t, f"UNKNOWN({t})")


def _mask_to_int(mask_obj) -> int:
    """
    Convert impacket ACCESS_MASK to int safely.
    """
    if isinstance(mask_obj, int):
        return mask_obj

    for attr in ("getValue", "mask"):
        try:
            val = getattr(mask_obj, attr)
            if callable(val):
                v = val()
                if isinstance(v, int):
                    return v
            elif isinstance(val, int):
                return val
        except Exception:
            pass

    try:
        raw = mask_obj.getData()
        if isinstance(raw, (bytes, bytearray)) and len(raw) >= 4:
            return int.from_bytes(raw[:4], "little", signed=False)
    except Exception:
        pass

    raise TypeError(f"Could not convert ACCESS_MASK to int: {type(mask_obj)}")


def _decode_rights(mask: int) -> List[str]:
    names = []
    for table in (DS_RIGHTS, STANDARD_RIGHTS, GENERIC_RIGHTS):
        for bit, name in table.items():
            if mask & bit:
                names.append(name)
    return names


def _key_rights(mask: int, bh_compat: bool = True) -> dict:
    has_write_owner = bool(mask & 0x00080000)
    has_write_dacl = bool(mask & 0x00040000)
    has_generic_all_direct = bool(mask & 0x10000000)
    has_gw_direct = bool(mask & 0x40000000)
    has_writeprop = bool(mask & 0x00000020)
    has_self = bool(mask & 0x00000008)
    has_gw_derived = bh_compat and (has_writeprop or has_self)

    need_ds = (
        (mask & 0x00000001) and
        (mask & 0x00000002) and
        (mask & 0x00000004) and
        (mask & 0x00000010) and
        (mask & 0x00000020) and
        (mask & 0x00000040) and
        (mask & 0x00000080) and
        (mask & 0x00000100)
    )
    need_std = (
        (mask & 0x00010000) and
        (mask & 0x00020000) and
        (mask & 0x00040000) and
        (mask & 0x00080000)
    )
    has_generic_all_derived = bool(need_ds and need_std)

    return {
        "WriteOwner": has_write_owner,
        "WriteDACL": has_write_dacl,
        "GenericAll_direct": has_generic_all_direct,
        "GenericAll_derived": has_generic_all_derived,
        "GenericWrite_direct": has_gw_direct,
        "GenericWrite_derived": has_gw_derived,
    }


def _format_bool(label: str, val: bool, alt: Optional[str] = None) -> str:
    return f"  - {label}: {('YES' if val else 'NO') if not alt else (alt if val else 'NO')}"


def _resolve_sid_safe(sid: str, resolver: Optional[Callable[[str], str]]) -> str:
    if not resolver:
        return sid
    try:
        return resolver(sid) or sid
    except Exception:
        return sid


def _ldap_value_to_text(value: Any) -> str:
    """Safely convert LDAP attribute values to display text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return str(value)
    return str(value)


def _ldap_attr_values(entry: Any, attr_name: str) -> List[Any]:
    """
    Best-effort LDAP entry attribute extraction.

    Supports common shapes returned by Impacket LDAPConnection.search(), custom
    wrapper dicts, and ldap3-like entries. This keeps parse_acl.py independent
    from the exact socket/wrapper implementation.
    """
    wanted = attr_name.lower()

    # ldap3 style: entry[attr].values or entry[attr].value
    try:
        attr = entry[attr_name]
        vals = getattr(attr, "values", None)
        if vals is not None:
            return list(vals)
        val = getattr(attr, "value", None)
        if val is not None:
            return [val]
    except Exception:
        pass

    # dict-style attributes/raw_attributes
    if isinstance(entry, dict):
        for container_name in ("attributes", "raw_attributes"):
            attrs = entry.get(container_name)
            if isinstance(attrs, dict):
                for k, v in attrs.items():
                    if str(k).lower() == wanted:
                        if isinstance(v, (list, tuple)):
                            return list(v)
                        return [v]

        # direct dict key
        for k, v in entry.items():
            if str(k).lower() == wanted:
                if isinstance(v, (list, tuple)):
                    return list(v)
                return [v]

    # Impacket SearchResultEntry shape: entry['attributes'] -> list of attrs
    try:
        attrs = entry["attributes"]
        for a in attrs:
            try:
                atype = _ldap_value_to_text(a["type"]).lower()
                if atype != wanted:
                    continue
                vals = a["vals"]
                return list(vals)
            except Exception:
                try:
                    atype = _ldap_value_to_text(getattr(a, "type", "")).lower()
                    if atype == wanted:
                        vals = getattr(a, "vals", [])
                        return list(vals)
                except Exception:
                    pass
    except Exception:
        pass

    # ldap3 entry_attributes_as_dict
    try:
        attrs = getattr(entry, "entry_attributes_as_dict", {})
        for k, v in attrs.items():
            if str(k).lower() == wanted:
                if isinstance(v, (list, tuple)):
                    return list(v)
                return [v]
    except Exception:
        pass

    return []


def _ldap_attr_first(entry: Any, attr_name: str) -> str:
    vals = _ldap_attr_values(entry, attr_name)
    if not vals:
        return ""
    return _ldap_value_to_text(vals[0]).strip()


def _ldap_entry_dn(entry: Any) -> str:
    """Best-effort DN extraction from common LDAP result shapes."""
    for attr in ("distinguishedName", "distinguishedname"):
        val = _ldap_attr_first(entry, attr)
        if val:
            return val

    if isinstance(entry, dict):
        for key in ("dn", "entry_dn", "objectName"):
            if entry.get(key):
                return _ldap_value_to_text(entry.get(key)).strip()

    for attr in ("entry_dn", "dn"):
        try:
            val = getattr(entry, attr)
            if val:
                return _ldap_value_to_text(val).strip()
        except Exception:
            pass

    try:
        val = entry["objectName"]
        if val:
            return _ldap_value_to_text(val).strip()
    except Exception:
        pass

    return ""


def _sid_to_ldap_filter_value(sid: str) -> Optional[str]:
    """
    Convert canonical SID string to escaped binary LDAP filter value.

    LDAP objectSid is stored as binary, so the reliable filter form is:
      (objectSid=\01\05...)
    """
    try:
        parts = sid.split("-")
        if len(parts) < 4 or parts[0] != "S":
            return None

        revision = int(parts[1])
        identifier_authority = int(parts[2])
        sub_auths = [int(x) for x in parts[3:]]

        raw = bytearray()
        raw.append(revision & 0xFF)
        raw.append(len(sub_auths) & 0xFF)
        raw.extend(identifier_authority.to_bytes(6, "big", signed=False))
        for sub in sub_auths:
            raw.extend(sub.to_bytes(4, "little", signed=False))

        return "".join(f"\\{b:02x}" for b in raw)
    except Exception:
        return None


def _domain_dn_from_dn(dn: str) -> str:
    """Extract DC=example,DC=local from any DN."""
    if not dn:
        return ""
    dc_parts = [p.strip() for p in dn.split(",") if p.strip().lower().startswith("dc=")]
    return ",".join(dc_parts)


def _domain_dn_from_entries(entries: Iterable[Tuple]) -> str:
    for entry in entries:
        try:
            dn = entry[0]
            base = _domain_dn_from_dn(dn)
            if base:
                return base
        except Exception:
            pass
    return ""


def _ldap_search_one(sock: Any, base_dn: str, ldap_filter: str, attributes: List[str]) -> Optional[Any]:
    """
    Search LDAP through either ACEVision's socket wrapper or the underlying
    LDAP connection. Returns the first result if available.
    """
    if not sock or not base_dn or not ldap_filter:
        return None

    candidates = [sock]
    for attr in (
        "ldap_connection",
        "ldap_conn",
        "connection",
        "conn",
        "ldap",
        "_ldap_connection",
    ):
        try:
            obj = getattr(sock, attr, None)
            if obj and obj not in candidates:
                candidates.append(obj)
        except Exception:
            pass

    for conn in candidates:
        search = getattr(conn, "search", None)
        if not callable(search):
            continue

        attempts = (
            lambda: search(searchBase=base_dn, searchFilter=ldap_filter, attributes=attributes, sizeLimit=1),
            lambda: search(searchFilter=ldap_filter, searchBase=base_dn, attributes=attributes, sizeLimit=1),
            lambda: search(base_dn, ldap_filter, attributes=attributes, sizeLimit=1),
            lambda: search(base_dn, ldap_filter, attributes),
        )

        for attempt in attempts:
            try:
                results = attempt()
                if not results:
                    continue
                if isinstance(results, tuple):
                    # Some wrappers return (success, results) or (results, controls)
                    for item in results:
                        if isinstance(item, (list, tuple)) and item:
                            return item[0]
                    continue
                if isinstance(results, (list, tuple)):
                    return results[0] if results else None
                return results
            except TypeError:
                continue
            except Exception:
                continue

    return None


def _principal_details_from_ldap_entry(entry: Any, sid: str) -> Optional[Dict[str, Any]]:
    if not entry:
        return None

    dn = _ldap_entry_dn(entry)
    object_classes = [_ldap_value_to_text(v).strip() for v in _ldap_attr_values(entry, "objectClass")]
    object_classes = [c for c in object_classes if c]

    name = (
        _ldap_attr_first(entry, "sAMAccountName")
        or _ldap_attr_first(entry, "cn")
        or _ldap_attr_first(entry, "name")
        or dn
        or sid
    )

    object_type = _classify_object_type(object_classes, dn)
    principal_type = _format_object_type_label(object_type)

    return {
        "sid": sid,
        "name": name,
        "dn": dn,
        "object_classes": object_classes,
        "object_type": object_type,
        "principal_type": principal_type,
    }


def _resolve_principal_details_via_ldap(sock: Any, sid: str, base_dn: str) -> Optional[Dict[str, Any]]:
    sid_filter = _sid_to_ldap_filter_value(sid)
    if not sid_filter:
        return None

    ldap_filter = f"(objectSid={sid_filter})"
    attrs = ["sAMAccountName", "cn", "name", "distinguishedName", "objectClass", "objectSid"]
    entry = _ldap_search_one(sock, base_dn, ldap_filter, attrs)
    return _principal_details_from_ldap_entry(entry, sid)


def _make_principal_details_resolver(
    sock: Any,
    entries: Iterable[Tuple],
    name_resolver: Optional[Callable[[str], str]] = None,
) -> Callable[[str], Dict[str, Any]]:
    """
    Build a cached SID -> LDAP object resolver.

    This is the global fix: every ACE principal SID can now become an object-aware
    principal with name, DN, objectClass, and object type.
    """
    entries_list = list(entries)
    base_dn = _domain_dn_from_entries(entries_list)
    cache: Dict[str, Dict[str, Any]] = {}

    def resolver(sid: str) -> Dict[str, Any]:
        if sid in cache:
            return cache[sid]

        details = _resolve_principal_details_via_ldap(sock, sid, base_dn)

        if not details:
            resolved_name = _resolve_sid_safe(sid, name_resolver)
            fallback_type = _classify_principal_type(resolved_name, sid)
            if fallback_type == "Unknown Object":
                fallback_type = "Unresolved"
            details = {
                "sid": sid,
                "name": resolved_name,
                "dn": "",
                "object_classes": [],
                "object_type": "Unknown",
                "principal_type": fallback_type,
            }

        cache[sid] = details
        return details

    # Expose the materialized entries so enumerate_acls_for_sid can avoid
    # consuming a generator twice.
    resolver.entries = entries_list  # type: ignore[attr-defined]
    return resolver


def _is_dn_under(dn: str, base_dn: str) -> bool:
    if not base_dn:
        return True
    dn_l, base_l = dn.lower(), base_dn.lower()
    return dn_l == base_l or dn_l.endswith("," + base_l)


def _get_dacl(sd) -> Optional[object]:
    try:
        return sd["Dacl"]  # type: ignore[index]
    except Exception:
        try:
            return getattr(sd, "dacl", None)
        except Exception:
            return None


def _extract_object_type_guid(ace) -> Optional[str]:
    """
    Extract ObjectType GUID from object ACEs parsed by Impacket.
    """
    try:
        ace_type = ace["AceType"]
        if ace_type not in OBJECT_ACE_TYPES:
            return None

        ace_data = ace["Ace"]

        flags = ace_data["Flags"]
        if not (flags & ACE_OBJECT_TYPE_PRESENT):
            return None

        raw = ace_data["ObjectType"]

        if raw in (None, b"", ""):
            return None

        if isinstance(raw, bytes) and len(raw) == 16:
            return str(uuid.UUID(bytes_le=raw)).lower()

        if isinstance(raw, bytearray) and len(raw) == 16:
            return str(uuid.UUID(bytes_le=bytes(raw))).lower()

        if isinstance(raw, str):
            val = raw.strip().lower()
            if val and val != "00000000-0000-0000-0000-000000000000":
                return val

        try:
            raw_bytes = bytes(raw)
            if len(raw_bytes) == 16:
                return str(uuid.UUID(bytes_le=raw_bytes)).lower()
        except Exception:
            pass

        try:
            val = str(raw).strip().lower()
            if val and val != "00000000-0000-0000-0000-000000000000":
                return val
        except Exception:
            pass

    except Exception:
        pass

    return None


def _resolve_extended_right(object_type_guid: Optional[str]) -> Optional[str]:
    if not object_type_guid:
        return None
    return EXTENDED_RIGHTS_GUIDS.get(object_type_guid.lower())


def _resolve_friendly_object_label(object_type_guid: Optional[str]) -> Optional[str]:
    if not object_type_guid:
        return None
    return FRIENDLY_OBJECT_TYPE_LABELS.get(object_type_guid.lower())


def _is_dcsync_guid(object_type_guid: Optional[str]) -> bool:
    if not object_type_guid:
        return False
    return object_type_guid.lower() in CRITICAL_DCSYNC_GUIDS


def _is_force_change_password_guid(object_type_guid: Optional[str]) -> bool:
    if not object_type_guid:
        return False
    return object_type_guid.lower() in FORCE_CHANGE_PASSWORD_GUIDS


def _is_object_ace_with_control_access(ace) -> bool:
    """
    Detect object ACEs where the mask includes ControlAccess (0x100).
    Useful for debugging if the GUID cannot be resolved yet.
    """
    try:
        ace_type = ace["AceType"]
        if ace_type not in OBJECT_ACE_TYPES:
            return False
        mask = _mask_to_int(ace["Ace"]["Mask"])
        return bool(mask & 0x00000100)
    except Exception:
        return False


def _should_print_ace(
    mask: int,
    only_escalation: bool,
    bh_compat: bool,
    object_type_guid: Optional[str] = None,
) -> bool:
    if not only_escalation:
        return True

    kk = _key_rights(mask, bh_compat)
    has_classic_escalation = any(
        [
            kk["WriteOwner"],
            kk["WriteDACL"],
            kk["GenericAll_direct"],
            kk["GenericAll_derived"],
            kk["GenericWrite_direct"],
            kk["GenericWrite_derived"],
        ]
    )

    has_dcsync = bool(object_type_guid and object_type_guid.lower() in CRITICAL_DCSYNC_GUIDS)
    has_force_change_password = bool(
        object_type_guid and object_type_guid.lower() in FORCE_CHANGE_PASSWORD_GUIDS
    )

    return has_classic_escalation or has_dcsync or has_force_change_password


def _classify_object_type(object_classes, dn: str = "") -> str:
    """
    Convert LDAP objectClass values into a simple ACEVision object type.
    This keeps the advisor logic readable and object-aware.
    """
    classes = [str(c).lower() for c in (object_classes or [])]
    dn_l = (dn or "").lower()

    if "domaindns" in classes:
        return "Domain"

    if "grouppolicycontainer" in classes:
        return "GPO"

    if "pkicertificatetemplate" in classes:
        return "Certificate Template"

    if "organizationalunit" in classes:
        return "OU"

    if "computer" in classes:
        return "Computer"

    if "group" in classes:
        return "Group"

    # Computer objects also include user in objectClass, so user must come after computer.
    if "user" in classes:
        return "User"

    # Fallback hints from DN when objectClass is unavailable or incomplete.
    if dn_l.startswith("dc=") and all(part.startswith("dc=") for part in dn_l.split(",")):
        return "Domain"

    if "cn=certificate templates" in dn_l:
        return "Certificate Template"

    if "cn=policies,cn=system" in dn_l:
        return "GPO"

    return "Unknown"



def _classify_principal_type(resolved_sid: str, sid: str = "") -> str:
    """
    Best-effort classification of the ACE principal.

    The target object type is known from LDAP objectClass. The principal comes
    from the ACE SID, so unless the SID resolver also returns LDAP objectClass,
    this function uses safe heuristics from the resolved name/SID.

    Future improvement: extend the SID resolver to return both name and
    objectClass so this can classify User/Group/Computer with LDAP certainty.
    """
    val = (resolved_sid or sid or "").strip()
    val_l = val.lower()

    if not val_l:
        return "Unknown Object"

    # Computer accounts conventionally end in $.
    if val_l.endswith("$"):
        return "Computer Object"

    # Common built-in/domain groups and SID patterns.
    group_keywords = (
        "domain admins",
        "enterprise admins",
        "schema admins",
        "domain users",
        "domain computers",
        "domain controllers",
        "cert publishers",
        "account operators",
        "server operators",
        "backup operators",
        "print operators",
        "dnsadmins",
        "remote management users",
        "remote desktop users",
    )
    if any(k in val_l for k in group_keywords):
        return "Group Object"

    # Well-known/domain relative IDs that are groups.
    group_rids = ("-512", "-513", "-514", "-515", "-516", "-517", "-518", "-519", "-520")
    if (sid or val).endswith(group_rids):
        return "Group Object"

    # If it resolved as DOMAIN\name and is not a known computer/group, user is
    # the most useful default for operator output.
    if "\\" in val:
        return "User Object"

    return "Unknown Object"


def _format_object_type_label(object_type: str) -> str:
    """Normalize object type labels for human-readable output."""
    safe = object_type or "Unknown"
    if safe in ("Unknown", "Unknown Object", "Unresolved"):
        return "Unresolved"
    if safe.endswith("Object"):
        return safe
    return f"{safe} Object"


def _format_target_type(object_type: str) -> str:
    return _format_object_type_label(object_type)


def _target_display_name(record: dict) -> str:
    """Return a short target name for critical finding banners."""
    dn = record.get("dn", "") or ""
    if _is_domain_dn(dn):
        return "Domain"

    # Prefer CN/OU/DC leading component instead of the full DN for the banner.
    first = dn.split(",", 1)[0] if dn else "Unknown"
    if "=" in first:
        return first.split("=", 1)[1]
    return first or "Unknown"


def _c(text: str, color: str) -> str:
    """ANSI color helper for terminal-friendly ACEVision output."""
    colors = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "cyan": "\033[96m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "blue": "\033[94m",
        "white": "\033[97m",
        "dim": "\033[2m",
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def _advisor_box_lines(title: str = "ACEVision Advisor") -> None:
    """Draw a clean, wider advisor banner."""
    width = 38
    print(_c("    ╔" + "═" * width + "╗", "yellow"))
    print(_c(f"    ║{title:^{width}}║", "yellow"))
    print(_c("    ╚" + "═" * width + "╝", "yellow"))


def _object_type_box(object_type: str) -> None:
    """Highlight the target LDAP object type because advisor recommendations depend on it."""
    width = 30
    safe_type = object_type or "Unknown"

    print(_c("    ╔" + "═" * width + "╗", "cyan"))
    print(_c(f"    ║{'Object Type':^{width}}║", "cyan"))
    print(_c("    ╠" + "═" * width + "╣", "cyan"))
    print(_c(f"    ║{safe_type:^{width}}║", "green"))
    print(_c("    ╚" + "═" * width + "╝", "cyan"))




def _trigger_right_box(right_found: str) -> None:
    """Highlight the effective right that triggered the advisor recommendation."""
    width = 30
    safe_right = right_found or "Unknown"

    print(_c("    ╔" + "═" * width + "╗", "yellow"))
    print(_c(f"    ║{'Trigger Right':^{width}}║", "yellow"))
    print(_c("    ╠" + "═" * width + "╣", "yellow"))
    print(_c(f"    ║{safe_right:^{width}}║", "green"))
    print(_c("    ╚" + "═" * width + "╝", "yellow"))


def _confidence_color(confidence: str) -> str:
    c = (confidence or "").lower()
    if c == "high":
        return "green"
    if c == "medium":
        return "yellow"
    if c == "low":
        return "red"
    return "white"


def _impact_color(impact: str) -> str:
    i = (impact or "").lower()
    if i == "critical":
        return "red"
    if i == "high":
        return "yellow"
    if i == "medium":
        return "yellow"
    if i == "low":
        return "green"
    return "white"



def _assessment_color(assessment: str) -> str:
    """Color-code advisor assessment labels."""
    a = (assessment or "").lower()
    if a in ("privilege escalation", "domain compromise", "critical"):
        return "red"
    if a in ("lateral movement", "persistence"):
        return "yellow"
    if a == "informational":
        return "green"
    return "white"


def _is_read_only_ace(mask: int) -> bool:
    """
    Identify ACEs that provide visibility but no direct object control.

    Example from Sauna:
      0x20014 = ListChildren + ReadProperty + ReadControl

    These permissions are useful for enumeration, but they do not directly grant
    ownership control, DACL control, object modification, password reset, or
    replication rights.
    """
    read_bits = (
        0x00000004 |  # ListChildren
        0x00000010 |  # ReadProperty
        0x00000080 |  # ListObject
        0x00020000 |  # ReadControl
        0x80000000    # GenericRead
    )

    control_or_write_bits = (
        0x00000001 |  # CreateChild
        0x00000002 |  # DeleteChild
        0x00000008 |  # Self
        0x00000020 |  # WriteProperty
        0x00000040 |  # DeleteTree
        0x00000100 |  # ControlAccess
        0x00010000 |  # Delete
        0x00040000 |  # WriteDACL
        0x00080000 |  # WriteOwner
        0x01000000 |  # AccessSystemSecurity
        0x10000000 |  # GenericAll
        0x40000000    # GenericWrite
    )

    return bool(mask & read_bits) and not bool(mask & control_or_write_bits)


def _print_informational_advisor(object_type: str, rights: Optional[List[str]] = None) -> None:
    """
    Advisor output for low-impact/read-only findings.

    This prevents beginners from treating every ACE as an attack path while still
    explaining why the ACE appeared in the output.
    """
    _advisor_box_lines()

    print(f"      {_c('Assessment:', 'cyan')} {_c('INFORMATIONAL', _assessment_color('Informational'))}")
    print(f"      {_c('Confidence:', 'cyan')} {_c('HIGH', _confidence_color('High'))}")
    print(f"      {_c('Likely Impact:', 'cyan')} {_c('LOW', _impact_color('Low'))}")
    print("")

    print(f"      {_c('Reason:', 'cyan')}")
    if object_type == "Domain":
        print("        Read-only permissions are common on Domain objects.")
    else:
        print("        The identified rights provide visibility but not control.")
    print("        No direct privilege escalation path identified.")
    print("")

    if rights:
        print(f"      {_c('Observed Read Rights:', 'cyan')}")
        for r in rights:
            print(f"        {_c('•', 'yellow')} {_c(r, 'white')}")
        print("")

    print(f"      {_c('Recommendation:', 'cyan')}")
    print("        Continue enumeration.")
    print("        Prioritize WriteOwner, WriteDACL, GenericAll,")
    print("        GenericWrite, ForceChangePassword, AddMember,")
    print("        and DCSync-related rights.")




def _outcome_color(outcome: str) -> str:
    """Color-code potential outcomes for readability."""
    o = (outcome or "").lower()

    green_keywords = (
        "password reset",
        "shadow credentials",
        "add yourself",
        "add a controlled user",
        "rbcd",
        "dcsync",
        "replicate",
        "extract krbtgt",
        "account takeover",
    )

    red_keywords = (
        "domain compromise",
        "dump domain hashes",
        "golden ticket",
        "critical",
    )

    yellow_keywords = (
        "attribute",
        "spn",
        "template",
        "certificate",
        "gpo",
        "policy",
        "object-specific",
    )

    if any(k in o for k in red_keywords):
        return "red"
    if any(k in o for k in green_keywords):
        return "green"
    if any(k in o for k in yellow_keywords):
        return "yellow"

    return "white"


def _print_suggested_flow(flow: Optional[List[str]]) -> None:
    if not flow:
        return

    print("")
    print(f"      {_c('Suggested Flow:', 'cyan')}")
    for idx, step in enumerate(flow):
        print(f"        {_c(step, 'white')}")
        if idx != len(flow) - 1:
            print(f"          {_c('↓', 'yellow')}")


def _print_advisor_block(
    recommended_label: str,
    recommended_value: str,
    why: str,
    outcomes: List[str],
    confidence: str = "High",
    impact: str = "High",
    no_dacl_required: bool = False,
    flow: Optional[List[str]] = None,
) -> None:
    """Pretty terminal output for the ACEVision recommendation engine."""
    _advisor_box_lines()

    if no_dacl_required:
        print(f"      {_c('No Additional DACL Modification Required.', 'green')}")
        print("")

    print(f"      {_c(recommended_label + ':', 'cyan')}")
    print(f"        {_c('➜', 'green')} {_c(recommended_value, 'green')}")
    print("")

    print(f"      {_c('Why?', 'cyan')}")
    print(f"        {why}")
    print("")

    print(
        f"      {_c('Confidence:', 'cyan')} "
        f"{_c(confidence.upper(), _confidence_color(confidence))}"
        f"    {_c('|', 'white')}    "
        f"{_c('Impact:', 'cyan')} "
        f"{_c(impact.upper(), _impact_color(impact))}"
    )
    print("")

    print(f"      {_c('Potential Outcomes:', 'cyan')}")
    for item in outcomes:
        print(f"        {_c('•', 'yellow')} {_c(item, _outcome_color(item))}")

    _print_suggested_flow(flow)


def _dacl_flow_step(right_found: str) -> str:
    """Return the correct flow step for rights that lead into DACL modification."""
    if right_found == "WriteOwner":
        return "Take ownership / modify DACL"
    if right_found == "WriteDACL":
        return "Modify DACL"
    return "Modify DACL"


def _print_acevision_recommendation(object_type: str, right_found: str) -> None:
    """
    Educational recommendation engine for ACEVision.

    Important distinction:
    - WriteOwner / WriteDACL usually need a DACL modification recommendation.
    - GenericAll / DCSync / ForceChangePassword already represent abuse-ready rights.
    """

    if right_found in ("WriteOwner", "WriteDACL"):
        if object_type == "User":
            _print_advisor_block(
                recommended_label="Recommended DACL",
                recommended_value="GenericAll",
                why="GenericAll provides broad control over a user object.",
                confidence="High",
                impact="High",
                outcomes=[
                    "Password Reset",
                    "Shadow Credentials",
                    "Attribute Modification",
                ],
                flow=[
                    right_found,
                    _dacl_flow_step(right_found),
                    "Grant GenericAll",
                    "Choose takeover method",
                ],
            )
            return

        if object_type == "Group":
            _print_advisor_block(
                recommended_label="Recommended DACL",
                recommended_value="WriteMembers",
                why="WriteMembers is the most direct path to group membership abuse.",
                confidence="High",
                impact="High",
                outcomes=[
                    "Add yourself to the group",
                    "Add a controlled user to the group",
                    "Inherit group privileges",
                ],
                flow=[
                    right_found,
                    _dacl_flow_step(right_found),
                    "Grant WriteMembers",
                    "Add controlled principal to group",
                ],
            )
            return

        if object_type == "Computer":
            _print_advisor_block(
                recommended_label="Recommended DACL",
                recommended_value="GenericAll",
                why="GenericAll provides broad control over the computer object.",
                confidence="High",
                impact="High",
                outcomes=[
                    "RBCD",
                    "Shadow Credentials",
                    "Computer object abuse",
                ],
                flow=[
                    right_found,
                    _dacl_flow_step(right_found),
                    "Grant GenericAll",
                    "Choose computer-object abuse path",
                ],
            )
            return

        if object_type == "Certificate Template":
            _print_advisor_block(
                recommended_label="Recommended DACL",
                recommended_value="GenericAll",
                why="Template control can lead to ESC4-style abuse.",
                confidence="High",
                impact="High",
                outcomes=[
                    "Modify certificate template",
                    "Enable dangerous enrollment settings",
                    "Certificate abuse path",
                ],
                flow=[
                    right_found,
                    _dacl_flow_step(right_found),
                    "Grant GenericAll",
                    "Modify template configuration",
                ],
            )
            return

        if object_type == "GPO":
            _print_advisor_block(
                recommended_label="Recommended DACL",
                recommended_value="GenericAll",
                why="GenericAll can allow full control of the GPO object.",
                confidence="High",
                impact="High",
                outcomes=[
                    "Modify GPO settings",
                    "Code execution through policy abuse",
                    "Persistence or privilege escalation",
                ],
                flow=[
                    right_found,
                    _dacl_flow_step(right_found),
                    "Grant GenericAll",
                    "Modify GPO",
                ],
            )
            return

        if object_type == "OU":
            _print_advisor_block(
                recommended_label="Recommended DACL",
                recommended_value="GenericAll",
                why="GenericAll can allow control over the OU and delegated permissions.",
                confidence="Medium",
                impact="Medium",
                outcomes=[
                    "Control delegated permissions",
                    "Influence child objects depending on inheritance",
                ],
                flow=[
                    right_found,
                    _dacl_flow_step(right_found),
                    "Grant GenericAll",
                    "Review inheritance impact",
                ],
            )
            return

        if object_type == "Domain":
            _print_advisor_block(
                recommended_label="Recommended DACL",
                recommended_value="DCSync Rights",
                why="WriteDACL over the domain can grant replication rights, enabling DCSync.",
                confidence="High",
                impact="Critical",
                outcomes=[
                    "Replicate directory secrets",
                    "Dump domain hashes",
                    "Extract KRBTGT hash",
                    "Domain compromise",
                ],
                flow=[
                    right_found,
                    _dacl_flow_step(right_found),
                    "Grant DCSync rights",
                    "Replicate directory secrets",
                    "Domain compromise",
                ],
            )
            return

        _print_advisor_block(
            recommended_label="Recommended DACL",
            recommended_value="GenericAll",
            why="GenericAll is the most flexible follow-up when object type is unknown.",
            confidence="Medium",
            impact="Medium",
            outcomes=["Object-specific abuse based on target type"],
            flow=[right_found, "Modify DACL", "Grant GenericAll", "Review object-specific abuse"],
        )
        return

    if right_found == "GenericAll":
        if object_type == "User":
            outcomes = ["Password Reset", "Shadow Credentials", "SPN / Attribute Manipulation"]
            flow = ["GenericAll", "No DACL change needed", "Choose takeover method"]
            impact = "High"
        elif object_type == "Group":
            outcomes = ["Add yourself to the group", "Add a controlled user to the group"]
            flow = ["GenericAll", "No DACL change needed", "Modify group membership"]
            impact = "High"
        elif object_type == "Computer":
            outcomes = ["RBCD", "Shadow Credentials", "Computer attribute abuse"]
            flow = ["GenericAll", "No DACL change needed", "Choose computer-object abuse path"]
            impact = "High"
        elif object_type == "Certificate Template":
            outcomes = ["ESC4-style template modification", "Certificate abuse path"]
            flow = ["GenericAll", "No DACL change needed", "Modify template configuration"]
            impact = "High"
        elif object_type == "GPO":
            outcomes = ["Modify GPO settings", "Push code execution through policy"]
            flow = ["GenericAll", "No DACL change needed", "Modify GPO"]
            impact = "High"
        elif object_type == "Domain":
            outcomes = [
                "Grant DCSync rights",
                "Replicate directory secrets",
                "Dump domain hashes",
                "Domain compromise",
            ]
            flow = ["GenericAll", "No DACL change needed", "Choose domain-control abuse path"]
            impact = "Critical"
        else:
            outcomes = ["Object-specific abuse based on target type"]
            flow = ["GenericAll", "No DACL change needed", "Review object type"]
            impact = "Medium"

        _print_advisor_block(
            recommended_label="Recommended Abuse Paths",
            recommended_value="GenericAll Abuse",
            why="GenericAll already provides full control over this object.",
            confidence="High",
            impact=impact,
            outcomes=outcomes,
            no_dacl_required=True,
            flow=flow,
        )
        return

    if right_found == "DCSync":
        _print_advisor_block(
            recommended_label="Recommended Abuse Path",
            recommended_value="DCSync",
            why="The required replication permissions are already present.",
            confidence="High",
            impact="Critical",
            outcomes=[
                "Dump domain hashes",
                "Extract KRBTGT hash",
                "Domain compromise",
            ],
            no_dacl_required=True,
            flow=["DCSync rights", "No DACL change needed", "Replicate directory secrets"],
        )
        return

    if right_found == "ForceChangePassword":
        _print_advisor_block(
            recommended_label="Recommended Abuse Path",
            recommended_value="Password Reset",
            why="The required reset-password permission is already present.",
            confidence="High",
            impact="High",
            outcomes=["Account takeover"],
            no_dacl_required=True,
            flow=["ForceChangePassword", "No DACL change needed", "Reset target password"],
        )
        return

    if right_found == "GenericWrite":
        if object_type == "User":
            outcomes = [
                "Targeted attribute modification",
                "SPN manipulation / Kerberoasting path",
                "Shadow Credentials if msDS-KeyCredentialLink is writable",
            ]
        elif object_type == "Group":
            outcomes = [
                "Modify writable group attributes",
                "Check whether membership-related rights are available",
            ]
        elif object_type == "Computer":
            outcomes = [
                "Attribute modification",
                "RBCD if msDS-AllowedToActOnBehalfOfOtherIdentity is writable",
            ]
        else:
            outcomes = ["Object-specific attribute abuse"]

        _print_advisor_block(
            recommended_label="Recommended Abuse Paths",
            recommended_value="GenericWrite Abuse",
            why="GenericWrite already allows targeted attribute modification.",
            confidence="Medium",
            impact="Medium",
            outcomes=outcomes,
            no_dacl_required=True,
            flow=["GenericWrite", "No DACL change needed", "Identify writable attributes", "Choose attribute-abuse path"],
        )
        return

    _advisor_box_lines()
    print(f"      {_c('No advisor rule available yet for this right.', 'yellow')}")


# ==================================================
# ACEVision Findings Summary Engine
# ==================================================

def _severity_for_finding(object_type: str, trigger_right: str) -> str:
    """Rank effective ACEVision findings for operator-first output."""
    obj = (object_type or "Unknown").lower()
    right = (trigger_right or "").lower()

    if obj == "domain" and right in ("dcsync", "genericall", "writedacl", "writeowner"):
        return "CRITICAL"
    if right == "dcsync":
        return "CRITICAL"
    if right == "genericall":
        return "CRITICAL" if obj == "domain" else "HIGH"
    if right in ("writedacl", "writeowner", "forcechangepassword"):
        return "HIGH"
    if right == "genericwrite":
        return "MEDIUM"
    if right == "informational":
        return "LOW"
    return "LOW"


def _severity_color(severity: str) -> str:
    s = (severity or "").upper()
    if s == "CRITICAL":
        return "red"
    if s == "HIGH":
        return "yellow"
    if s == "MEDIUM":
        return "yellow"
    if s == "LOW":
        return "green"
    return "white"


def _finding_sort_key(finding: dict) -> int:
    """Lower number means higher priority."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    right_order = {
        "DCSync": 0,
        "GenericAll": 1,
        "WriteDACL": 2,
        "WriteOwner": 3,
        "ForceChangePassword": 4,
        "GenericWrite": 5,
        "Informational": 99,
    }
    return (
        severity_order.get(finding.get("severity", "LOW"), 9) * 100
        + right_order.get(finding.get("right", ""), 50)
    )


def _is_domain_dn(dn: str) -> bool:
    """Return True for root domain DN like DC=spookysec,DC=local."""
    dn_l = (dn or "").lower()
    if not dn_l.startswith("dc="):
        return False
    return all(part.strip().startswith("dc=") for part in dn_l.split(","))


def _normalize_findings_for_summary(findings: List[dict]) -> List[dict]:
    """
    Convert raw ACE findings into attack-path findings.

    Important: DCSync and domain GenericAll are domain-control paths.
    If those are present on the root domain object, inherited/effective copies
    on child containers, OUs, users, groups, DNS objects, etc. are noise.
    """
    if not findings:
        return []

    domain_dcsync = [
        f for f in findings
        if f.get("right") == "DCSync"
        and (f.get("object_type") == "Domain" or _is_domain_dn(f.get("dn", "")))
    ]
    domain_genericall = [
        f for f in findings
        if f.get("right") == "GenericAll"
        and (f.get("object_type") == "Domain" or _is_domain_dn(f.get("dn", "")))
    ]

    normalized: List[dict] = []

    # Keep one DCSync finding for the domain. This prevents inherited/effective
    # DCSync ACEs from flooding the summary for every child object.
    if domain_dcsync:
        best = sorted(domain_dcsync, key=_finding_sort_key)[0].copy()
        best["object_type"] = "Domain"
        best["severity"] = "CRITICAL"
        normalized.append(best)

    # Keep one GenericAll domain-control finding when present.
    if domain_genericall:
        best = sorted(domain_genericall, key=_finding_sort_key)[0].copy()
        best["object_type"] = "Domain"
        best["severity"] = "CRITICAL"
        normalized.append(best)

    for f in findings:
        right = f.get("right")

        # Domain-level DCSync already explains the attack path.
        if right == "DCSync" and domain_dcsync:
            continue

        # Domain GenericAll already dominates child-object GenericAll noise.
        if right == "GenericAll" and domain_genericall and f.get("object_type") != "Domain":
            continue

        # Avoid re-adding the exact domain findings already normalized above.
        if right == "DCSync" and f in domain_dcsync:
            continue
        if right == "GenericAll" and f in domain_genericall:
            continue

        normalized.append(f)

    return normalized


def _dedupe_findings(findings: List[dict]) -> List[dict]:
    """Collapse duplicate summary findings into one line per attack path."""
    seen = set()
    unique = []

    for finding in sorted(_normalize_findings_for_summary(findings), key=_finding_sort_key):
        key = (
            finding.get("right"),
            finding.get("object_type"),
            finding.get("dn"),
            finding.get("sid"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    return unique


def _print_findings_summary(
    principal: str,
    findings: List[dict],
    total_matching_aces: int,
    objects_with_findings: int,
    verbose: bool = False,
) -> None:
    """Print the operator-first ACEVision summary before raw ACE detail."""
    unique_findings = _dedupe_findings(findings)

    print("")
    print(_c("═══════════════════════════════════════", "red"))
    print(_c("🔥 ACEVision Findings Summary", "red"))
    print(_c("═══════════════════════════════════════", "red"))
    print("")
    print(f"Principal: {principal or 'N/A'}")
    principal_types = sorted({
        f.get("principal_type", "Unresolved")
        for f in unique_findings
        if f.get("principal_type")
    })
    if len(principal_types) == 1:
        print(f"Principal Type: {principal_types[0]}")
    elif len(principal_types) > 1:
        print(f"Principal Type: Mixed ({', '.join(principal_types)})")
    print("")

    for severity in ("CRITICAL", "HIGH", "MEDIUM"):
        group = [f for f in unique_findings if f.get("severity") == severity]
        print(_c(severity, _severity_color(severity)))
        print("────────" if severity == "CRITICAL" else "────")
        if group:
            for f in group:
                right = f.get("right", "Unknown")
                obj = f.get("object_type", "Unknown")
                dn = f.get("dn", "")
                print(f"✅ {right} ({obj})")
                if dn:
                    print(_c(f"   ↳ {dn}", "dim"))
        else:
            print("None")
        print("")

    print(f"Objects with matching ACEs: {objects_with_findings}")
    print(f"Matching ACEs Found:       {total_matching_aces}")
    print("")

    if unique_findings:
        print("Summary shows deduplicated attack paths, not every inherited/effective ACE.")

    if verbose:
        print("Verbose mode enabled: full ACE details below.")
    else:
        print("Run with --verbose to display full ACE details.")

    print(_c("═══════════════════════════════════════", "red"))
    print("")


def _print_default_advisor_blocks(findings: List[dict]) -> None:
    """
    Print ACEVision Advisor blocks in default mode without raw ACE noise.

    Default mode should still explain the path. It should only suppress
    verbose evidence such as raw ACE type, mask, GUID, and key-right details.
    """
    unique_findings = _dedupe_findings(findings)

    # Advisor de-confliction:
    # If the same principal has multiple rights over the same target,
    # show only the strongest/most direct abuse path. This prevents
    # duplicate Advisor blocks such as DCSync + GenericAll on the domain.
    advisor_priority = {
        "DCSync": 100,
        "GenericAll": 90,
        "WriteDACL": 80,
        "WriteOwner": 70,
        "GenericWrite": 60,
        "ForceChangePassword": 50,
    }

    best_findings = {}

    for finding in unique_findings:
        key = (
            finding.get("resolved_sid") or finding.get("sid"),
            finding.get("dn"),
            finding.get("object_type"),
        )

        current = best_findings.get(key)

        if not current:
            best_findings[key] = finding
            continue

        new_score = advisor_priority.get(finding.get("right"), 0)
        old_score = advisor_priority.get(current.get("right"), 0)

        if new_score > old_score:
            best_findings[key] = finding

    unique_findings = list(best_findings.values())

    actionable_rights = {
        "DCSync",
        "GenericAll",
        "WriteDACL",
        "WriteOwner",
        "ForceChangePassword",
        "GenericWrite",
    }

    printed_any = False

    for finding in unique_findings:
        right = finding.get("right")
        if right not in actionable_rights:
            continue

        dn = finding.get("dn", "")
        object_type = finding.get("object_type", "Unknown")

        if not printed_any:
            print(_c("[ADVISOR] ACEVision Recommended Next Steps", "cyan"))
            print("")
            printed_any = True

        if dn:
            print(f"[ACL] {dn}")

        _object_type_box(object_type)
        _trigger_right_box(right)
        _print_acevision_recommendation(object_type, right)
        print("")


def _get_trigger_right(
    mask: int,
    object_type_guid: Optional[str],
    bh_compat: bool = True,
) -> Optional[str]:
    """Pick the strongest effective right for advisor/summary output."""
    kk = _key_rights(mask, bh_compat)
    is_dcsync = _is_dcsync_guid(object_type_guid)
    is_force_change_password = _is_force_change_password_guid(object_type_guid)

    if is_dcsync:
        return "DCSync"
    if kk["GenericAll_direct"] or kk["GenericAll_derived"]:
        return "GenericAll"
    if is_force_change_password:
        return "ForceChangePassword"
    if kk["GenericWrite_direct"] or kk["GenericWrite_derived"]:
        return "GenericWrite"
    if kk["WriteDACL"]:
        return "WriteDACL"
    if kk["WriteOwner"]:
        return "WriteOwner"

    return None


def _build_ace_record(
    dn: str,
    object_type: str,
    ace,
    resolve_sid: Optional[Callable[[str], str]],
    bh_compat: bool,
    resolve_sid_details: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> dict:
    """Normalize ACE data once so summary and verbose output use the same facts."""
    sid = ace["Ace"]["Sid"].formatCanonical()
    mask = _mask_to_int(ace["Ace"]["Mask"])
    acetype = ace["AceType"]
    object_type_guid = _extract_object_type_guid(ace)
    extended_right = _resolve_extended_right(object_type_guid)
    friendly_object_label = _resolve_friendly_object_label(object_type_guid)
    is_dcsync = _is_dcsync_guid(object_type_guid)
    is_force_change_password = _is_force_change_password_guid(object_type_guid)
    is_control_access_object_ace = _is_object_ace_with_control_access(ace)
    rights = _decode_rights(mask)
    unknown_bits = mask & (~ALL_RIGHTS_MASK)
    kk = _key_rights(mask, bh_compat)
    trigger_right = _get_trigger_right(mask, object_type_guid, bh_compat)

    try:
        ace_flags = hex(ace["Ace"]["Flags"])
    except Exception:
        ace_flags = "N/A"

    principal_details: Dict[str, Any] = {}
    if resolve_sid_details:
        try:
            principal_details = resolve_sid_details(sid) or {}
        except Exception:
            principal_details = {}

    resolved_sid = (
        principal_details.get("name")
        or principal_details.get("resolved_sid")
        or _resolve_sid_safe(sid, resolve_sid)
    )
    principal_type = (
        principal_details.get("object_type")
        or principal_details.get("principal_type")
        or _classify_principal_type(resolved_sid, sid)
    )
    if principal_type == "Unknown Object":
        principal_type = "Unresolved"

    return {
        "dn": dn,
        "object_type": object_type,
        "ace": ace,
        "sid": sid,
        "resolved_sid": resolved_sid,
        "principal_type": principal_type,
        "principal_dn": principal_details.get("dn", ""),
        "principal_object_classes": principal_details.get("object_classes", []),
        "mask": mask,
        "acetype": acetype,
        "object_type_guid": object_type_guid,
        "extended_right": extended_right,
        "friendly_object_label": friendly_object_label,
        "is_dcsync": is_dcsync,
        "is_force_change_password": is_force_change_password,
        "is_control_access_object_ace": is_control_access_object_ace,
        "rights": rights,
        "unknown_bits": unknown_bits,
        "kk": kk,
        "trigger_right": trigger_right,
        "ace_flags": ace_flags,
    }


def _print_ace_record(record: dict) -> None:
    """Verbose ACE output, preserved from the original parser behavior."""
    mask = record["mask"]
    kk = record["kk"]
    rights = record["rights"]
    unknown_bits = record["unknown_bits"]
    trigger_right = record["trigger_right"]
    object_type = record["object_type"]

    print("  🔐 ACE Summary:")
    print(f"    ACE Type:       {_ace_type_name(record['acetype'])}")
    print(f"    SID:            {record['sid']}")
    print(f"    Resolved SID:   {record['resolved_sid']}")
    print(f"    Principal Type: {record.get('principal_type', 'Unresolved')}")
    if record.get("principal_dn"):
        print(f"    Principal DN:   {record.get('principal_dn')}")
    print(f"    Mask (hex):     {hex(mask)}")
    print(f"    ObjectType:     {record['object_type_guid'] or 'N/A'}")
    print(f"    ACE Flags:      {record['ace_flags']}")

    if record["extended_right"]:
        print(f"    ExtendedRight:  {record['extended_right']}")

    if record["friendly_object_label"]:
        print(f"    BloodHound:     {record['friendly_object_label']}")

    if record["is_dcsync"]:
        print("    [!] DCSync-capable permission detected")

    if record["is_force_change_password"]:
        print("    [!] ForceChangePassword-capable permission detected")

    if record["is_control_access_object_ace"] and not record["extended_right"]:
        print("    [i] Object ACE with ControlAccess detected, but GUID was not resolved yet.")

    print("    Rights:")

    if rights:
        for r in rights:
            print(f"      ✅ {r}")
    else:
        print("      – No classic rights were recognized in this mask")

    if unknown_bits:
        print(f"      … Unknown bits: {hex(unknown_bits)}")

    print("    Key rights (quick check):")
    print(_format_bool("  WriteOwner", kk["WriteOwner"]))
    print(_format_bool("  WriteDACL", kk["WriteDACL"]))

    if kk["GenericAll_direct"]:
        print(_format_bool("  GenericAll", True, "YES (direct)"))
    elif kk["GenericAll_derived"]:
        print(_format_bool("  GenericAll", True, "YES (equivalent)"))
    else:
        print(_format_bool("  GenericAll", False))

    if kk["GenericWrite_direct"]:
        print(_format_bool("  GenericWrite", True, "YES (direct)"))
    elif kk["GenericWrite_derived"]:
        print(_format_bool("  GenericWrite", True, "YES (derived)"))
    else:
        print(_format_bool("  GenericWrite", False))

    if (not kk["GenericWrite_direct"]) and kk["GenericWrite_derived"]:
        print("    [i] GenericWrite (derived) inferred from WriteProperty/Self (BH compatibility).")

    if record["is_dcsync"]:
        print("    [i] This ACE grants critical replication permissions over the domain object.")

    if record["is_force_change_password"]:
        print("    [i] This ACE grants Reset Password / ForceChangePassword over the user object.")

    if trigger_right:
        _trigger_right_box(trigger_right)
        _print_acevision_recommendation(object_type, trigger_right)
    elif _is_read_only_ace(mask):
        _trigger_right_box("Informational")
        _print_informational_advisor(object_type, rights)

    print("")




def _is_critical_attack_path(record: dict) -> bool:
    """Return True when a finding should be announced immediately during long scans."""
    right = record.get("trigger_right")
    object_type = record.get("object_type")
    dn = record.get("dn", "")

    # Domain-control paths should get early operator feedback.
    if object_type == "Domain" or _is_domain_dn(dn):
        return right in ("DCSync", "GenericAll", "WriteDACL", "WriteOwner")

    return False


def _print_scan_start_once(state: dict) -> None:
    """Print the scan-start message once when ACEVision becomes chatty."""
    if state.get("scan_started_printed"):
        return

    print("")
    print(_c("[SCAN] Processing ACLs...", "cyan"), flush=True)
    state["scan_started_printed"] = True


def _print_critical_finding(state: dict, principal: str, record: dict) -> None:
    """Print the critical finding banner once with object-aware context."""
    if state.get("critical_announced"):
        return

    right = record.get("trigger_right", "Unknown")
    principal_name = principal or record.get("resolved_sid") or record.get("sid") or "Unknown"
    principal_type = record.get("principal_type", "Unresolved")

    target_object_type = (
        "Domain"
        if _is_domain_dn(record.get("dn", ""))
        else record.get("object_type", "Unknown")
    )
    target_name = _target_display_name(record)
    target_type = _format_target_type(target_object_type)

    print("")
    print(_c("[🔥] CRITICAL FINDING", "red"), flush=True)
    print(f"   Principal:      {principal_name}", flush=True)
    print(f"   Principal Type: {principal_type}", flush=True)
    if record.get("principal_dn"):
        print(f"   Principal DN:   {record.get('principal_dn')}", flush=True)
    print("")
    print(f"   Right:          {right}", flush=True)
    print("")
    print(f"   Target:         {target_name}", flush=True)
    print(f"   Target Type:    {target_type}", flush=True)
    print("")

    state["critical_announced"] = True

def _maybe_enable_progress(state: dict, threshold_seconds: float = 5.0) -> None:
    """
    Enable heartbeat output only when the scan takes long enough to feel stalled.

    Fast scans stay clean. Slow scans automatically become communicative.
    If a critical path was found during a fast portion of the scan, store it
    and only announce it if the scan actually becomes slow.
    """
    if state.get("progress_enabled"):
        return

    elapsed = time.time() - state["start_time"]
    if elapsed >= threshold_seconds:
        _print_scan_start_once(state)

        pending = state.get("pending_critical_record")
        if pending and not state.get("critical_announced"):
            _print_critical_finding(
                state,
                state.get("pending_critical_principal") or "",
                pending,
            )

        print(_c("[SCAN] Continuing enumeration...", "cyan"), flush=True)
        state["progress_enabled"] = True


def _announce_critical_once(state: dict, principal: str, record: dict) -> None:
    """
    Announce the first critical path only when the scan is already chatty.

    This keeps fast scans clean. If the scan later crosses the slow threshold,
    the pending critical finding is printed then.
    """
    if state.get("critical_announced"):
        return

    if not _is_critical_attack_path(record):
        return

    if not state.get("pending_critical_record"):
        state["pending_critical_record"] = record
        state["pending_critical_principal"] = principal

    if not state.get("progress_enabled"):
        return

    _print_scan_start_once(state)
    _print_critical_finding(state, principal, record)

def parse_acl_entries(
    entries: Iterable[Tuple],
    filter_sid: Optional[str] = None,
    resolve_sid: Optional[Callable[[str], str]] = None,
    only_escalation: bool = False,
    bh_compat: bool = True,
    verbose: bool = False,
    resolve_sid_details: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> None:
    """
    Parse ACL entries and print an operator-first findings summary.

    Default behavior:
    - Collect matching ACEs.
    - Print a prioritized, deduplicated ACEVision Findings Summary.
    - Suppress noisy raw ACE details.

    Verbose behavior:
    - Print the same summary first.
    - Then print full ACE evidence and Advisor blocks.
    """
    records: List[dict] = []
    findings: List[dict] = []
    object_headers = {}
    processing_errors: List[str] = []

    # UX state: default output stays quiet for fast scans, but slow/critical scans
    # receive heartbeat output so users do not think ACEVision is frozen.
    scan_state = {
        "start_time": time.time(),
        "progress_enabled": False,
        "scan_started_printed": False,
        "critical_announced": False,
        "pending_critical_record": None,
        "pending_critical_principal": None,
        "objects_processed": 0,
        "next_object_heartbeat": 500,
    }

    # Best principal label available before any ACE records are collected.
    # If --resolve-sids is enabled, this will be replaced later by resolved_sid.
    principal_hint = filter_sid or "All principals"

    for entry_data in entries:
        scan_state["objects_processed"] += 1
        _maybe_enable_progress(scan_state)

        if (
            scan_state.get("progress_enabled")
            and scan_state["objects_processed"] >= scan_state["next_object_heartbeat"]
        ):
            print(
                _c(f"[SCAN] Processed {scan_state['objects_processed']} objects...", "cyan"),
                flush=True,
            )
            scan_state["next_object_heartbeat"] += 500
        if len(entry_data) == 3:
            dn, sd, object_classes = entry_data
        else:
            dn, sd = entry_data
            object_classes = []

        object_type = _classify_object_type(object_classes, dn)
        dacl = _get_dacl(sd)
        aces = getattr(dacl, "aces", None) if dacl is not None else None

        if not dacl or not aces:
            if verbose and not filter_sid:
                print(f"[ACL] {dn}")
                _object_type_box(object_type)
                try:
                    ctrl = getattr(sd, "Control", 0)
                    present = bool(ctrl & SE_DACL_PRESENT)
                    print(f"    [!] No DACL or no ACEs present (SE_DACL_PRESENT={present})")
                except Exception:
                    print("    [!] No DACL or no ACEs present")
            continue

        object_had_record = False

        for ace in aces:
            try:
                sid = ace["Ace"]["Sid"].formatCanonical()

                if filter_sid and sid != filter_sid:
                    continue

                record = _build_ace_record(
                    dn,
                    object_type,
                    ace,
                    resolve_sid,
                    bh_compat,
                    resolve_sid_details=resolve_sid_details,
                )

                if only_escalation:
                    if not (
                        _should_print_ace(
                            record["mask"],
                            only_escalation,
                            bh_compat,
                            record["object_type_guid"],
                        )
                        or record["is_control_access_object_ace"]
                    ):
                        continue

                records.append(record)
                object_had_record = True
                object_headers[dn] = object_type

                if records and principal_hint == (filter_sid or "All principals"):
                    principal_hint = record.get("resolved_sid") or principal_hint

                trigger_right = record["trigger_right"]
                if trigger_right:
                    _announce_critical_once(scan_state, principal_hint, record)
                    findings.append(
                        {
                            "dn": dn,
                            "object_type": object_type,
                            "right": trigger_right,
                            "severity": _severity_for_finding(object_type, trigger_right),
                            "sid": record["sid"],
                            "resolved_sid": record["resolved_sid"],
                            "principal_type": record.get("principal_type", "Unresolved"),
                            "principal_dn": record.get("principal_dn", ""),
                        }
                    )

            except Exception as e:
                processing_errors.append(f"{dn}: {e}")

        if verbose and not filter_sid and not object_had_record:
            print(f"[ACL] {dn}")
            _object_type_box(object_type)
            print("    [!] No relevant ACEs to display with the current filters.")

    if filter_sid:
        principal = filter_sid
        if records:
            principal = records[0].get("resolved_sid") or filter_sid
    else:
        principal = "All principals"

    if not records:
        print("")
        print(_c("[SUMMARY]", "cyan"))
        if filter_sid:
            print(f"  No ACEs found for SID: {filter_sid}")
            print("  No control relationships identified.")
        else:
            print("  No ACEs matched the current filters.")
        return

    _print_findings_summary(
        principal=principal,
        findings=findings,
        total_matching_aces=len(records),
        objects_with_findings=len(object_headers),
        verbose=verbose,
    )

    if processing_errors and verbose:
        print(_c("[WARNINGS]", "yellow"))
        for err in processing_errors:
            print(f"  [!] Error processing ACE: {err}")
        print("")

    if not verbose:
        _print_default_advisor_blocks(findings)
        return

    current_dn = None
    for record in records:
        dn = record["dn"]
        if dn != current_dn:
            current_dn = dn
            print(f"[ACL] {dn}")
            _object_type_box(record["object_type"])

        _print_ace_record(record)


def enumerate_acls_for_sid(
    sock,
    filter_sid: Optional[str],
    target_dn: Optional[str] = None,
    resolve_sid: Optional[Callable[[str], str]] = None,
    resolve_sid_details: Optional[Callable[[str], Dict[str, Any]]] = None,
    only_escalation: bool = False,
    bh_compat: bool = True,
    verbose: bool = False,
) -> None:
    entries = list(sock.get_effective_control_entries())

    if target_dn:
        entries = [
            entry
            for entry in entries
            if _is_dn_under(entry[0], target_dn)
        ]

    if resolve_sid_details is None:
        resolve_sid_details = _make_principal_details_resolver(
            sock=sock,
            entries=entries,
            name_resolver=resolve_sid,
        )

    parse_acl_entries(
        entries=entries,
        filter_sid=filter_sid,
        resolve_sid=resolve_sid,
        only_escalation=only_escalation,
        bh_compat=bh_compat,
        verbose=verbose,
        resolve_sid_details=resolve_sid_details,
    )

def check_writeowner_for_dn(sock, target_dn: str, sid: str) -> bool:
    entries = sock.get_effective_control_entries()

    for entry_data in entries:
        dn, sd = entry_data[0], entry_data[1]

        if dn.lower() != target_dn.lower():
            continue

        dacl = _get_dacl(sd)
        aces = getattr(dacl, "aces", None) if dacl else None

        if not aces:
            continue

        for ace in aces:
            try:
                if ace["Ace"]["Sid"].formatCanonical() != sid:
                    continue

                mask = _mask_to_int(ace["Ace"]["Mask"])
                has_wo = bool(mask & 0x00080000)

                print(
                    f"[CHECK] {dn} — SID {sid} WriteOwner: "
                    f"{'YES' if has_wo else 'NO'} (mask={hex(mask)})"
                )

                return has_wo

            except Exception:
                continue

    print(f"[CHECK] {target_dn} — no ACE found for SID {sid}")
    return False


def decode_mask(mask: int) -> List[str]:
    return _decode_rights(mask)


def summarize_mask(mask: int, bh_compat: bool = True) -> dict:
    return _key_rights(mask, bh_compat)
