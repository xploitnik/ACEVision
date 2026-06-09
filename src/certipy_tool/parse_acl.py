


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

def parse_acl_entries(
    entries: Iterable[Tuple],
    filter_sid: Optional[str] = None,
    resolve_sid: Optional[Callable[[str], str]] = None,
    only_escalation: bool = False,
    bh_compat: bool = True,
) -> None:
    """
    Parse and print ACL entries.

    Noise reduction behavior:
    - When --filter-sid is used, ACEVision only prints objects where that SID has a matching ACE.
    - Empty/non-matching objects are suppressed.
    - If no matching ACEs are found across the search, print one clean summary message.
    """
    findings_found = 0
    objects_with_findings = 0

    for entry_data in entries:
        if len(entry_data) == 3:
            dn, sd, object_classes = entry_data
        else:
            dn, sd = entry_data
            object_classes = []

        object_type = _classify_object_type(object_classes, dn)

        dacl = _get_dacl(sd)
        aces = getattr(dacl, "aces", None) if dacl is not None else None

        # With --filter-sid, suppress empty objects completely.
        # Without --filter-sid, keep the old visibility for general debugging/enumeration.
        if not dacl or not aces:
            if filter_sid:
                continue

            print(f"[ACL] {dn}")
            _object_type_box(object_type)
            try:
                ctrl = getattr(sd, "Control", 0)
                present = bool(ctrl & SE_DACL_PRESENT)
                print(f"    [!] No DACL or no ACEs present (SE_DACL_PRESENT={present})")
            except Exception:
                print("    [!] No DACL or no ACEs present")
            continue

        printed = False
        header_printed = False

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

                if not header_printed:
                    print(f"[ACL] {dn}")
                    _object_type_box(object_type)
                    header_printed = True
                    objects_with_findings += 1

                printed = True
                findings_found += 1
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

                #
                # ACEVision Advisor Priority Engine
                #
                # Prefer the strongest effective right over lower-level precursor rights.
                # Example: if an ACE contains WriteOwner + WriteDACL + GenericAll,
                # the advisor should explain GenericAll abuse directly instead of
                # recommending another DACL modification.
                #
                trigger_right = None

                if is_dcsync:
                    trigger_right = "DCSync"
                elif kk["GenericAll_direct"] or kk["GenericAll_derived"]:
                    trigger_right = "GenericAll"
                elif is_force_change_password:
                    trigger_right = "ForceChangePassword"
                elif kk["GenericWrite_direct"] or kk["GenericWrite_derived"]:
                    trigger_right = "GenericWrite"
                elif kk["WriteDACL"]:
                    trigger_right = "WriteDACL"
                elif kk["WriteOwner"]:
                    trigger_right = "WriteOwner"

                if trigger_right:
                    _trigger_right_box(trigger_right)
                    _print_acevision_recommendation(object_type, trigger_right)
                elif _is_read_only_ace(mask):
                    _trigger_right_box("Informational")
                    _print_informational_advisor(object_type, rights)

                print("")

            except Exception as e:
                # With --filter-sid, keep real processing errors visible because they may hide findings.
                print(f"    [!] Error processing ACE: {e}")

        # Noise reduction: when filtering by SID, do not print every object where the SID was absent.
        if filter_sid and not printed:
            continue
        elif not filter_sid and not printed:
            print(f"[ACL] {dn}")
            _object_type_box(object_type)
            print("    [!] No relevant ACEs to display with the current filters.")

    if filter_sid and findings_found == 0:
        print("")
        print(_c("[SUMMARY]", "cyan"))
        print(f"  No ACEs found for SID: {filter_sid}")
        print("  No control relationships identified.")
    elif filter_sid:
        print("")
        print(_c("[SUMMARY]", "cyan"))
        print(f"  Objects with matching ACEs: {objects_with_findings}")
        print(f"  Matching ACEs found:       {findings_found}")

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
            entry
            for entry in entries
            if _is_dn_under(entry[0], target_dn)
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





