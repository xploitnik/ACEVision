# -*- coding: utf-8 -*-
#
# ACEVision - Active Directory ACE analysis engine
#
from typing import Callable, Iterable, List, Optional, Tuple
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


def parse_acl_entries(
    entries: Iterable[Tuple[str, SR_SECURITY_DESCRIPTOR]],
    filter_sid: Optional[str] = None,
    resolve_sid: Optional[Callable[[str], str]] = None,
    only_escalation: bool = False,
    bh_compat: bool = True,
) -> None:
    for dn, sd in entries:
        print(f"[ACL] {dn}")

        dacl = _get_dacl(sd)
        aces = getattr(dacl, "aces", None) if dacl is not None else None

        if not dacl or not aces:
            try:
                ctrl = getattr(sd, "Control", 0)
                present = bool(ctrl & SE_DACL_PRESENT)
                print(f"    [!] No DACL or no ACEs present (SE_DACL_PRESENT={present})")
            except Exception:
                print("    [!] No DACL or no ACEs present")
            continue

        printed = False

        for ace in aces:
            try:
                sid = ace["Ace"]["Sid"].formatCanonical()

                if filter_sid and sid != filter_sid:
                    continue

                mask = _mask_to_int(ace["Ace"]["Mask"])
                acetype = ace["AceType"]
                object_type_guid = _extract_object_type_guid(ace)
                extended_right = _resolve_extended_right(object_type_guid)
                friendly_object_label = _resolve_friendly_object_label(object_type_guid)

                is_dcsync = _is_dcsync_guid(object_type_guid)
                is_force_change_password = _is_force_change_password_guid(object_type_guid)
                is_control_access_object_ace = _is_object_ace_with_control_access(ace)

                if only_escalation:
                    if not (
                        _should_print_ace(mask, only_escalation, bh_compat, object_type_guid)
                        or is_control_access_object_ace
                    ):
                        continue

                printed = True
                rights = _decode_rights(mask)
                unknown_bits = mask & (~ALL_RIGHTS_MASK)

                print("  🔐 ACE Summary:")
                print(f"    ACE Type:       {_ace_type_name(acetype)}")
                print(f"    SID:            {sid}")

                resolved = _resolve_sid_safe(sid, resolve_sid)
                print(f"    Resolved SID:   {resolved}")
                print(f"    Mask (hex):     {hex(mask)}")
                print(f"    ObjectType:     {object_type_guid or 'N/A'}")

                try:
                    print(f"    ACE Flags:      {hex(ace['Ace']['Flags'])}")
                except Exception:
                    print("    ACE Flags:      N/A")

                if extended_right:
                    print(f"    ExtendedRight:  {extended_right}")

                if friendly_object_label:
                    print(f"    BloodHound:     {friendly_object_label}")

                if is_dcsync:
                    print("    [!] DCSync-capable permission detected")

                if is_force_change_password:
                    print("    [!] ForceChangePassword-capable permission detected")

                if is_control_access_object_ace and not extended_right:
                    print("    [i] Object ACE with ControlAccess detected, but GUID was not resolved yet.")

                print("    Rights:")

                if rights:
                    for r in rights:
                        print(f"      ✅ {r}")
                else:
                    print("      – No classic rights were recognized in this mask")

                if unknown_bits:
                    print(f"      … Unknown bits: {hex(unknown_bits)}")

                kk = _key_rights(mask, bh_compat)

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

                if is_dcsync:
                    print("    [i] This ACE grants critical replication permissions over the domain object.")

                if is_force_change_password:
                    print("    [i] This ACE grants Reset Password / ForceChangePassword over the user object.")

                print("")

            except Exception as e:
                print(f"    [!] Error processing ACE: {e}")

        if filter_sid and not printed:
            print(f"    [!] No ACEs referencing SID {filter_sid} were found on this object.")
        elif not printed:
            print("    [!] No relevant ACEs to display with the current filters.")


def enumerate_acls_for_sid(
    sock,
    filter_sid: Optional[str],
    target_dn: Optional[str] = None,
    resolve_sid: Optional[Callable[[str], str]] = None,
    only_escalation: bool = False,
    bh_compat: bool = True,
) -> None:
    entries = sock.get_effective_control_entries()

    if target_dn:
        entries = [
            (dn, sd)
            for dn, sd in entries
            if _is_dn_under(dn, target_dn)
        ]

    parse_acl_entries(
        entries,
        filter_sid,
        resolve_sid,
        only_escalation,
        bh_compat
    )


def check_writeowner_for_dn(sock, target_dn: str, sid: str) -> bool:
    entries = sock.get_effective_control_entries()

    for dn, sd in entries:
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







