#!/usr/bin/env python3
"""
normalize.py — UNIFIED normalizer for every dataset_v2 case.

One engine. Each case is a tiny declarative build/case.json (selection + roles +
derivations + metadata). This tool loads the events (Splunk export authoritative,
raw log as fallback/verify), parses Windows event XML generically (Sysmon +
Security), assigns A0/EV ids, applies deterministic derivations, and emits the
neutral alert_package + selection_metadata, validated against the schemas.

  python3 normalize.py --case <dir>                 # from Splunk export (default, authoritative)
  python3 normalize.py --case <dir> --from-splunk P  # from export P
  python3 normalize.py --case <dir> --from-log       # from the raw source log (reference / Splunk-free)
  python3 normalize.py --case <dir> --verify-log     # re-derive from raw log, diff vs delivered (no write)
"""
import argparse
import base64
import binascii
import hashlib
import html
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent                 # SafeSOC/tools
SCH  = HERE / "schema"                                  # schemas travel with the tools
PROJECT = HERE.parent
# Raw-source operations first use repository-relative locations. External public
# corpus checkouts can be supplied without editing this file.
ATTACK_DATA_ROOT = Path(
    os.environ.get("SAFESOC_DATA", PROJECT / "data_sources" / "attack_data")
).expanduser()
OTRF_ROOT = Path(
    os.environ.get("OTRF_DATA", PROJECT / "data_sources" / "otrf_selected_raw")
).expanduser()
STAGED_LOGS = PROJECT / "_splunk_ingest"


def _root_of(cfg):
    return OTRF_ROOT if "mordor_log" in cfg else ATTACK_DATA_ROOT


def _source_resolution_hint(cfg):
    if "mordor_log" in cfg:
        return (
            f"Set OTRF_DATA to the public corpus root, or restore the selected raw "
            f"files under {OTRF_ROOT}."
        )
    return (
        f"Set SAFESOC_DATA to the public corpus root, or restore a hash-identical "
        f"copy under {STAGED_LOGS}."
    )


def _resolve_source(cfg, case_dir, source_log):
    """Resolve a raw source, falling back to the hash-identical staged project copy."""
    direct = _root_of(cfg) / source_log
    if direct.exists():
        return direct
    provenance = case_dir / "source" / "provenance.json"
    if not provenance.exists():
        raise FileNotFoundError(
            f"Raw source not found and no provenance fallback exists: {direct}. "
            f"{_source_resolution_hint(cfg)}"
        )
    rows = json.loads(provenance.read_text(encoding="utf-8")).get("sources", [])
    expected = next((row.get("sha256") for row in rows if row.get("source_log") == source_log), None)
    if not expected:
        raise FileNotFoundError(
            f"Raw source not found and provenance has no SHA-256 for {source_log}. "
            f"{_source_resolution_hint(cfg)}"
        )
    stored = cfg.get("metadata", {}).get("stored_filename", "")
    stored_parts = [part.strip() for part in stored.split(" + ") if part.strip()]
    source_rows = cfg.get("sources") or [{"source_log": cfg.get("source_log")}]
    source_names = [row.get("source_log") for row in source_rows]
    if source_log in source_names and len(stored_parts) == len(source_names):
        candidate = STAGED_LOGS / stored_parts[source_names.index(source_log)]
        if candidate.exists() and sha256(candidate) == expected:
            return candidate
    matches = [path for path in STAGED_LOGS.glob("*") if path.is_file() and sha256(path) == expected]
    if len(matches) != 1:
        raise FileNotFoundError(
            f"Raw-source fallback expected one staged SHA-256 match for {source_log}, "
            f"found {len(matches)}. {_source_resolution_hint(cfg)}"
        )
    return matches[0]

# --------------------------------------------------------------------------- #
#  Generic Windows-event XML parsing
# --------------------------------------------------------------------------- #
def sha256(path):
    digest = hashlib.sha256()
    digest.update(Path(path).read_bytes())
    return digest.hexdigest()


def _unxml(s):
    return (s.replace("&amp;","&").replace("&lt;","<").replace("&gt;",">")
             .replace("&quot;",'"').replace("&apos;","'"))
def sx(e,*names):
    for n in names:
        m=re.search(rf"Name='{n}'>([^<]*)", e)
        if m: return _unxml(m.group(1))
    return ""
def _tag(e,t):
    m=re.search(rf"<{t}[^>]*>([^<]*)</{t}>", e) or re.search(rf"<{t}[^>]*>([^<]*)", e)
    return m.group(1) if m else ""
def eid(e):
    return _tag(e, "EventID")


def rid(e):
    return _tag(e, "EventRecordID")


def comp(e):
    return _tag(e, "Computer")


def chan(e):
    return _tag(e, "Channel")


def prov(e):
    m=re.search(r"<Provider Name='([^']+)'", e); return m.group(1) if m else ""
def stime(e):
    m=re.search(r"SystemTime='([0-9T:\.\-]+)", e); return m.group(1) if m else ""
def utcz(e):
    t=stime(e); return t if t.endswith("Z") else t+"Z"

# event_code -> (event_type, [(sysmon_field(s), neutral_attr), ...])  (order preserved)
FIELD_MAP = {
 "1":  ("process_create", [("ProcessGuid","process_guid"),("ProcessId","process_id"),("Image","image"),
        ("OriginalFileName","original_file_name"),("CommandLine","command_line"),("CurrentDirectory","current_directory"),
        ("User","user"),("IntegrityLevel","integrity_level"),("Hashes","hashes"),
        ("ParentProcessGuid","parent_process_guid"),("ParentProcessId","parent_process_id"),
        ("ParentImage","parent_image"),("ParentCommandLine","parent_command_line")]),
 "3":  ("network_connection", [("ProcessGuid","process_guid"),("ProcessId","process_id"),("Image","image"),
        ("User","user"),("Protocol","protocol"),("Initiated","initiated"),("SourceIp","source_ip"),
        ("SourcePort","source_port"),("DestinationIp","destination_ip"),("DestinationHostname","destination_hostname"),
        ("DestinationPort","destination_port")]),
 "8":  ("create_remote_thread", [("SourceProcessGuid","source_process_guid"),("SourceImage","source_image"),
        ("TargetProcessGuid","target_process_guid"),("TargetImage","target_image"),
        ("StartAddress","start_address"),("StartModule","start_module"),("StartFunction","start_function")]),
 "10": ("process_access", [(("SourceProcessGUID","SourceProcessGuid"),"source_process_guid"),
        ("SourceProcessId","source_process_id"),("SourceImage","source_image"),
        (("TargetProcessGUID","TargetProcessGuid"),"target_process_guid"),
        ("TargetProcessId","target_process_id"),("TargetImage","target_image"),
        ("GrantedAccess","granted_access"),("CallTrace","call_trace")]),
 "11": ("file_create", [("ProcessGuid","process_guid"),("ProcessId","process_id"),("Image","image"),
        ("TargetFilename","target_filename"),("CreationUtcTime","creation_utc_time")]),
 "12": ("registry_object_change", [("ProcessGuid","process_guid"),("ProcessId","process_id"),("Image","image"),
        ("TargetObject","target_object"),("EventType","registry_event"),("User","user")]),
 "13": ("registry_value_set", [("ProcessGuid","process_guid"),("Image","image"),
        ("TargetObject","target_object"),("Details","details"),("EventType","registry_event")]),
 "22": ("dns_query", [("ProcessGuid","process_guid"),("Image","image"),
        ("QueryName","query_name"),("QueryResults","query_results")]),
 "19": ("wmi_event_filter", [("Operation","operation"),("Name","filter_name"),
        ("EventNamespace","event_namespace"),("Query","query"),("User","user")]),
 "20": ("wmi_event_consumer", [("Operation","operation"),("Name","consumer_name"),
        ("Type","consumer_type"),("Destination","destination"),("User","user")]),
 "21": ("wmi_filter_to_consumer_binding", [("Operation","operation"),("Consumer","consumer"),
        ("Filter","filter"),("User","user")]),
 "4688": ("process_create", [("NewProcessName","new_process_name"),("NewProcessId","new_process_id"),
        ("ParentProcessName","parent_process_name"),("ProcessId","creator_process_id"),
        ("SubjectUserName","subject_user_name"),("SubjectDomainName","subject_domain_name"),
        ("SubjectLogonId","subject_logon_id"),("MandatoryLabel","mandatory_label"),("CommandLine","command_line")]),
 "4624": ("logon", [("TargetUserName","target_user_name"),("TargetDomainName","target_domain_name"),
        ("LogonType","logon_type"),("IpAddress","ip_address"),("IpPort","ip_port"),
        ("WorkstationName","workstation_name"),("LogonProcessName","logon_process"),
        ("AuthenticationPackageName","auth_package"),("SubjectUserName","subject_user_name"),
        ("ProcessName","process_name"),("ElevatedToken","elevated_token")]),
 "4625": ("failed_logon", [("TargetUserName","target_user_name"),("TargetDomainName","target_domain_name"),
        ("LogonType","logon_type"),("IpAddress","ip_address"),("IpPort","ip_port"),
        ("WorkstationName","workstation_name"),("Status","status"),("SubStatus","sub_status"),
        ("FailureReason","failure_reason"),("LogonProcessName","logon_process"),
        ("AuthenticationPackageName","auth_package"),("SubjectUserName","subject_user_name"),
        ("ProcessName","process_name")]),
 "5145": ("network_share_object_access", [("ShareName","share_name"),("ShareLocalPath","share_local_path"),
        ("RelativeTargetName","relative_target"),("SubjectUserName","subject_user_name"),
        ("SubjectDomainName","subject_domain_name"),("IpAddress","ip_address"),("IpPort","ip_port"),
        ("AccessMask","access_mask"),("ObjectType","object_type")]),
 "1102": ("security_log_cleared", [("SubjectUserName","subject_user_name"),("SubjectDomainName","subject_domain_name")]),
}

def project(e):
    code=eid(e)
    if code=="4698":  # Security: a scheduled task was created — parse the embedded task XML
        tcm=re.search(r"Name='TaskContent'>(.*?)</Data>", e, re.S)
        tc=html.unescape(tcm.group(1)) if tcm else ""
        g=lambda pat:(re.search(pat,tc,re.S) or [None,""])[1].strip()
        attrs={"task_name": sx(e,"TaskName"),
               "subject_user": (sx(e,"SubjectDomainName")+"\\"+sx(e,"SubjectUserName")).strip("\\"),
               "action_command": g(r"<Command>(.*?)</Command>"),
               "action_arguments": g(r"<Arguments>(.*?)</Arguments>"),
               "run_as": g(r"<UserId>(.*?)</UserId>") or g(r"<GroupId>(.*?)</GroupId>"),
               "run_level": g(r"RunLevel>(.*?)</"),
               "author": g(r"<Author>(.*?)</Author>"),
               "triggers": ",".join(re.findall(r"<(\w*Trigger)\b", tc))}
        return "scheduled_task_created", {k:v for k,v in attrs.items() if v}
    et, fields = FIELD_MAP.get(code, ("other", []))
    attrs={}
    for spec, attr in fields:
        names = spec if isinstance(spec, tuple) else (spec,)
        v = sx(e, *names)
        if v != "": attrs[attr]=v
    if not fields:  # unknown code -> project all EventData fields faithfully
        for m in re.finditer(r"Name='([^']+)'>([^<]*)", e):
            attrs[m.group(1)] = _unxml(m.group(2))
    return et, attrs

def item(by_rid, evid, r, is_alert=False):
    e=by_rid[r]; et,attrs=project(e)
    b={"evidence_id":evid,"event_time_utc":utcz(e),"event_type":et,
       "source_event":{"provider":prov(e) or "Microsoft-Windows-Sysmon",
                       "channel":chan(e) or "Microsoft-Windows-Sysmon/Operational",
                       "event_code":int(code_of(e)),"event_record_id":r},
       "computer":comp(e),"attributes":attrs}
    if is_alert:
        b={"evidence_id":"A0","is_triggering_alert":True,**{k:v for k,v in b.items() if k!="evidence_id"}}
    return b
def code_of(e):
    return eid(e)

def decode_base64_utf16le(cmd):
    m=re.search(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{20,})", cmd, re.I)
    if not m:
        return ""
    try:
        return base64.b64decode(m.group(1) + "==").decode("utf-16le", "ignore")
    except (binascii.Error, ValueError, UnicodeError):
        return ""
def ps_deobfuscate_concat(cmd):
    # concatenate single-quoted string fragments inside (...), then apply .Replace('X',[char]N)
    m=re.search(r"\(\s*((?:'[^']*'\s*\+\s*)+'[^']*')\s*\)", cmd)
    if not m: return ""
    s="".join(re.findall(r"'([^']*)'", m.group(1)))
    r=re.search(r"\.replace\(\s*'([^']*)'\s*,\s*(?:\[[^\]]*\]\s*)*\[char\]\s*(\d+)", cmd, re.I)
    if r: s=s.replace(r.group(1), chr(int(r.group(2))))
    return s
DERIVERS={"base64_utf16le": decode_base64_utf16le, "ps_deobfuscate_concat": ps_deobfuscate_concat}

# --------------------------------------------------------------------------- #
#  Neutralisation: redact answer-leaking tokens from the MODEL-VISIBLE package
#  only (MITRE technique IDs + named test-frameworks/tools). Applied inside
#  build_package so the export-built and raw-built packages neutralise
#  identically (byte-identity preserved); the true raw stays in provenance.json.
# --------------------------------------------------------------------------- #
LEAK_RX = re.compile(
    r"(T\d{4}(?:[._]\d{3})?)"                  # group 1: MITRE technique IDs (T1234 or T1234.001) -> [id]
    r"|(at0micstrong)"                            # group 2: test-only credential -> [redacted-password]
    r"|(atomic[\s_-]*red[\s_-]*team|atomictestservice|atomicservice|atomics|atomic"
    r"|allthethings|redcanaryco|redcanary|purplesharp)",   # group 3: test frameworks/tools -> [x]
    re.I)
def _leak_sub(m):
    if m.group(1): return "[id]"
    if m.group(2): return "[redacted-password]"
    return "[x]"
def neutralize(value):
    return LEAK_RX.sub(_leak_sub, value) if isinstance(value, str) else value

# Leakage can also hide inside a base64 PowerShell -EncodedCommand: the plaintext blob passes LEAK_RX
# untouched, but decoding it (UTF-16LE) can reveal framework names / technique IDs — e.g. the Atomic Red
# Team harness (`Import-Module ...AtomicRedTeam...; Invoke-AtomicTest T####`) carried in a
# parent_command_line. So we decode every -EncodedCommand, neutralise the DECODED text with the same
# LEAK_RX, and re-encode. Deterministic, so export- and raw-built packages stay byte-identical.
_ENC_RX = re.compile(r"(-e(?:nc|ncodedcommand)?\s+)([A-Za-z0-9+/=]{20,})", re.I)
def _reencode_neutralized(b64):
    try:
        text = base64.b64decode(b64 + "==").decode("utf-16le", "ignore")
    except (binascii.Error, ValueError, UnicodeError):
        return b64
    clean = neutralize(text)
    if clean == text: return b64                     # nothing to redact -> leave the original bytes
    return base64.b64encode(clean.encode("utf-16le")).decode("ascii")
def _neut_str(s):
    # neutralise plaintext OUTSIDE base64 spans and the decoded content INSIDE them, so the plaintext
    # pass can never corrupt a base64 blob (split keeps the -Enc prefix + blob as separate pieces).
    parts = _ENC_RX.split(s)                          # [text, (prefix, b64, text)*]
    res = [neutralize(parts[0])]
    for k in range(1, len(parts), 3):
        res += [parts[k], _reencode_neutralized(parts[k + 1]), neutralize(parts[k + 2])]
    return "".join(res)
def _neut(o):
    if isinstance(o, str):  return _neut_str(o)
    if isinstance(o, list): return [_neut(x) for x in o]
    if isinstance(o, dict): return {k:_neut(v) for k,v in o.items()}
    return o

def _redact_model_visible_literals(pkg, cfg):
    """Apply exact, case-scoped replacements while preserving event structure.

    This handles answer-revealing literals that are specific to one capture and
    therefore do not belong in the global framework/technique redaction regex.
    Every configured source literal must match at least once so config drift
    cannot silently leave a leak in the model-visible package.
    """
    replacements = cfg.get("model_visible_literal_redactions", {})
    if not replacements:
        return pkg
    if not all(isinstance(source, str) and source for source in replacements):
        raise ValueError("model-visible literal redaction sources must be non-empty strings")
    if not all(isinstance(replacement, str) for replacement in replacements.values()):
        raise ValueError("model-visible literal redaction replacements must be strings")

    counts = {source: 0 for source in replacements}

    def redact(value):
        if isinstance(value, str):
            for source, replacement in replacements.items():
                matches = value.count(source)
                if matches:
                    counts[source] += matches
                    value = value.replace(source, replacement)
            return value
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    redacted = redact(pkg)
    unmatched = sorted(source for source, count in counts.items() if count == 0)
    if unmatched:
        raise ValueError(f"model-visible literal redaction source absent: {unmatched}")
    return redacted

# Host/domain anonymisation: map every computer (FQDN, short name, domain, netbios) in the
# package to generic host-NN / corp.local, so the package never betrays its host, environment,
# or which corpus it came from (dmevals.local, attackrange.local, ...). Deterministic from the
# sorted computer list, so export- and raw-built packages stay byte-identical.
def _anon_hosts(pkg):
    comps=sorted({c for c in pkg["observed_context"]["computers"] if c})
    m={}
    for i,c in enumerate(comps,1):
        parts=c.split("."); short=parts[0]; dom=".".join(parts[1:])
        m[c.lower()]=f"host-{i:02d}"+(".corp.local" if dom else "")
        m[short.lower()]=f"host-{i:02d}"
        # Windows machine accounts appear as the NetBIOS name (short name truncated to 15 chars) + '$',
        # e.g. computer 'win-host-mhaag-attack-range-569' -> subject 'WORKGROUP\\WIN-HOST-MHAAG-$'. That
        # truncated form never matches the full/short keys above, so it would leak. Map it too.
        nb=short[:15].rstrip("-_.")
        if len(nb)>=8 and nb.lower()!=short.lower(): m.setdefault(nb.lower(), f"host-{i:02d}")
        if dom:
            m[dom.lower()]="corp.local"; m[dom.split(".")[0].lower()]="corp"
    # identifying human usernames -> user-NN (keep well-known/service accounts: generic + triage-meaningful)
    WELL_KNOWN={"administrator","system","localservice","networkservice","local service",
                "network service","anonymous","guest","-","defaultaccount","iusr",""}
    unames=set()
    for u in pkg["observed_context"].get("users",[]):
        name=u.split("\\")[-1].strip().rstrip("$")
        if name.lower() not in WELL_KNOWN and not re.match(r"host-\d",name,re.I):
            unames.add(name)
    for i,name in enumerate(sorted(unames),1):
        m.setdefault(name.lower(), f"user-{i:02d}")
    # environment backstop: known corpus domains must NEVER survive, even if a Computer field was a short
    # name and the domain wasn't derived above (defensive; the computer-derived map above is primary).
    for env in ("attackrange.local","dmevals.local"): m.setdefault(env, "corp.local")
    for env in ("attackrange","dmevals"):             m.setdefault(env, "corp")
    if not m: return pkg
    rx=re.compile("|".join(re.escape(k) for k in sorted(m,key=len,reverse=True)),re.I)
    sub=lambda s: rx.sub(lambda mo:m[mo.group(0).lower()],s)
    def walk(o):
        if isinstance(o,str):  return sub(o)
        if isinstance(o,list): return [walk(x) for x in o]
        if isinstance(o,dict): return {k:walk(v) for k,v in o.items()}
        return o
    return walk(pkg)

# --------------------------------------------------------------------------- #
#  Event loading (Splunk export authoritative; raw log fallback/verify)
# --------------------------------------------------------------------------- #
def _sensor_of(e):        # from a raw event's provider/channel (export path)
    p=((prov(e) or "")+" "+(chan(e) or "")).lower()
    if "sysmon" in p:
        return "sysmon"
    if "powershell" in p:
        return "powershell"
    return "security"


def _sensor_from_channel(ch):    # from an already-projected item's channel (metadata path)
    c=(ch or "").lower()
    if "sysmon" in c:
        return "sysmon"
    if "powershell" in c:
        return "powershell"
    return "security"


def _role_lookup_key(event_record_id, channel, multi):
    if not multi:
        return event_record_id
    if ":" in event_record_id:
        return event_record_id
    return _sensor_from_channel(channel) + ":" + event_record_id

# --- stanza (key=value) Security log support: convert to the XML the engine already parses ---
STANZA_MAP = {   # EventCode -> { stanza Message field (optionally "Section|Field") : XML Data Name }
 "4688": {"New Process Name":"NewProcessName","New Process ID":"NewProcessId",
          "Creator Process Name":"ParentProcessName","Creator Process ID":"ProcessId",
          "Process Command Line":"CommandLine","Mandatory Label":"MandatoryLabel",
          "Creator Subject|Account Name":"SubjectUserName","Creator Subject|Account Domain":"SubjectDomainName",
          "Creator Subject|Logon ID":"SubjectLogonId"},
 "4624": {"New Logon|Account Name":"TargetUserName","New Logon|Account Domain":"TargetDomainName",
          "Logon Type":"LogonType","Source Network Address":"IpAddress","Workstation Name":"WorkstationName",
          "Logon Process":"LogonProcessName","Authentication Package":"AuthenticationPackageName"},
 "4625": {"Account For Which Logon Failed|Account Name":"TargetUserName","Logon Type":"LogonType",
          "Source Network Address":"IpAddress","Workstation Name":"WorkstationName","Failure Reason":"FailureReason"},
 "5140": {"Subject|Account Name":"SubjectUserName","Share Name":"ShareName","Source Address":"IpAddress"},
 "5145": {"Subject|Account Name":"SubjectUserName","Share Name":"ShareName","Relative Target Name":"RelativeTargetName","Source Address":"IpAddress"},
 "4719": {"Subject|Account Name":"SubjectUserName","Category":"Category","Subcategory":"Subcategory"},
 "1102": {"Subject|Account Name":"SubjectUserName","Subject|Domain Name":"SubjectDomainName"},
}
def _stanza_fields(block):
    fields={}; section=""
    mi=block.find("Message=")
    for line in (block[mi:] if mi>=0 else block).splitlines():
        mv=re.match(r"^\t*([A-Za-z][A-Za-z /]+?):\t+(.*\S)\s*$", line)
        ms=re.match(r"^\t*([A-Za-z][A-Za-z /]+?):\s*$", line)
        if mv:
            fn,fv=mv.group(1).strip(),mv.group(2).strip()
            fields.setdefault(fn,fv)
            if section: fields.setdefault(section+"|"+fn,fv)
        elif ms:
            section=ms.group(1).strip()
    return fields
def _stanza_to_xml(block):
    g=lambda k:(re.search(rf"(?m)^{re.escape(k)}=(.*)$",block) or [None,""])[1].strip()
    code=g("EventCode"); computer=g("ComputerName"); rec=g("RecordNumber")
    h=re.match(r"\s*(\d{2})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([AP]M)", block)
    iso=""
    if h:
        mo,da,yr,hh,mi,ss,ap=h.groups(); hh=int(hh)
        if ap=="PM" and hh!=12: hh+=12
        if ap=="AM" and hh==12: hh=0
        iso=f"{yr}-{mo}-{da}T{hh:02d}:{mi}:{ss}.000000000Z"   # attack_range VMs log local=UTC
    fields=_stanza_fields(block)
    pick=lambda src: fields.get(src) or (fields.get(src.split("|")[-1],"") if "|" in src else "")
    data="".join(f"<Data Name='{xn}'>{html.escape(pick(src),quote=False)}</Data>"
                 for src,xn in STANZA_MAP.get(code,{}).items() if pick(src))
    return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            f"<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{code}</EventID>"
            f"<TimeCreated SystemTime='{iso}'/><EventRecordID>{rec}</EventRecordID>"
            f"<Channel>Security</Channel><Computer>{computer}</Computer></System>"
            f"<EventData>{data}</EventData></Event>")
def _to_xml(raw):
    if "<Event" in raw[:200]: return raw
    return _stanza_to_xml(raw) if "EventCode=" in raw else raw
def read_raw(path):
    txt=path.read_text(encoding="utf-8",errors="ignore")
    if "<Event" in txt[:3000]:
        return re.findall(r"<Event\b.*?</Event>", txt, re.S)
    return [_stanza_to_xml(b) for b in re.split(r"(?m)^(?=\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M\s*$)", txt) if "EventCode=" in b]

# --- OTRF Security-Datasets (mordor NDJSON) support: convert each flat event to the same
#     synthetic <Event> XML the engine already parses. mordor field names match Sysmon's
#     <Data Name='...'> exactly (Image/CommandLine/TargetUserName/...), so FIELD_MAP works
#     unchanged. RecordNumber is the stable record id. ---
MORDOR_SYS={"@timestamp","@version","EventReceivedTime","EventTime","Keywords","Message","Opcode",
  "OpcodeValue","ProviderGuid","Severity","SeverityValue","SourceModuleName","SourceModuleType",
  "Task","ThreadID","Version","host","port","tags","ExecutionProcessID","SourceName","Hostname",
  "Channel","EventID","RecordNumber","Type","UtcTime","AccountType","Category","EventType"}
MORDOR_TEXT_REPAIRS={
    # The APT29 export contains a UTF-8 U+202E marker decoded once as Windows-1252.
    "â€®": "\u202e",
}
def _repair_mordor_text(value):
    text=str(value)
    for source,replacement in MORDOR_TEXT_REPAIRS.items():
        text=text.replace(source,replacement)
    return text
def _mordor_time(ev):
    t=(ev.get("UtcTime") or ev.get("EventTime") or ev.get("@timestamp") or "").strip().replace(" ","T")
    return t if (not t or t.endswith("Z")) else t+"Z"
def _mordor_to_xml(ev, rec=None):
    code=str(ev.get("EventID","")); ch=ev.get("Channel",""); cp=ev.get("Hostname","")
    prov=ev.get("SourceName","") or ("Microsoft-Windows-Sysmon" if "ysmon" in ch else "Microsoft-Windows-Security-Auditing")
    rec=str(rec if rec is not None else (ev.get("RecordNumber") or "")); iso=_mordor_time(ev)
    data="".join(f"<Data Name='{k}'>{html.escape(_repair_mordor_text(v),quote=False)}</Data>"
                 for k,v in ev.items() if k not in MORDOR_SYS and v not in (None,"",[]))
    if code=="13": data+="<Data Name='EventType'>SetValue</Data>"   # mordor's EventType is NXLog INFO; EID13 is always a value-set
    return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            f"<Provider Name='{prov}'/><EventID>{code}</EventID>"
            f"<TimeCreated SystemTime='{iso}'/><EventRecordID>{rec}</EventRecordID>"
            f"<Channel>{ch}</Channel><Computer>{cp}</Computer></System><EventData>{data}</EventData></Event>")
def read_mordor(path):
    p=Path(path)
    if p.suffix==".zip":
        import zipfile
        with zipfile.ZipFile(p) as z:
            nm=next(n for n in z.namelist() if n.endswith(".json"))
            for ln in z.open(nm):
                ln=ln.strip()
                if ln:
                    try:
                        yield json.loads(ln)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
    else:
        for ln in p.open(encoding="utf-8",errors="ignore"):
            ln=ln.strip()
            if ln:
                try:
                    yield json.loads(ln)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
def _load_mordor(cfg, case_dir):
    multi="sources" in cfg; path=_resolve_source(cfg,case_dir,cfg["mordor_log"]); keyed={}; hf=cfg.get("computer")
    for i,ev in enumerate(read_mordor(path),1):
        rec=str(ev.get("RecordNumber") or ev.get("EventRecordID") or i)   # atomic datasets lack a record id -> 1-based line index
        sn=_sensor_from_channel(ev.get("Channel","")); cp=ev.get("Hostname","")
        if multi:
            if not any(sn==s["sensor"] and (not s.get("computer") or cp.startswith(s["computer"])) for s in cfg["sources"]): continue
            keyed[sn+":"+rec]=_mordor_to_xml(ev,rec)
        else:
            if hf and not cp.startswith(hf): continue
            keyed[rec]=_mordor_to_xml(ev,rec)
    return keyed, f"mordor ({Path(cfg['mordor_log']).name})"

def load_events(cfg, case_dir, mode, explicit_export):
    # Returns a dict keyed by record id (single-source) or "sensor:record_id" (multi-source
    # Tier-2 fusion, when case.json has a "sources" list). Record ids collide across sensor
    # logs, so multi-source keys must carry the sensor.
    if "mordor_log" in cfg:                         # OTRF Security-Datasets (single mordor JSON, split by Channel/Hostname)
        return _load_mordor(cfg, case_dir)
    multi = "sources" in cfg
    keyed={}
    if mode in ("log","verify"):
        srcs = cfg["sources"] if multi else [{"sensor":None,"source_log":cfg["source_log"],"computer":cfg.get("computer")}]
        for src in srcs:
            log = _resolve_source(cfg,case_dir,src["source_log"]); cf=src.get("computer")   # optional host filter (multi-host logs collide on record id)
            for e in read_raw(log):
                if cf and not comp(e).startswith(cf): continue
                keyed[(src["sensor"]+":"+rid(e)) if multi else rid(e)] = e
        return keyed, (f"raw logs [{','.join(s['sensor'] for s in srcs)}]" if multi else f"raw log ({Path(cfg['source_log']).name})")
    export = Path(explicit_export) if explicit_export else (case_dir / cfg.get("staged_export","extracted/events.json"))
    if not export.exists():
        sys.exit(f"ERROR: Splunk export not found at {export}\n"
                 f"       Run the export in queries/retrieval_spec.md, or use --from-log.")
    sys.path.insert(0, str(HERE))
    from splunk_export_loader import load_events_from_export
    sensor_host = {s["sensor"]:s.get("computer") for s in cfg["sources"]} if multi else {}
    for e in load_events_from_export(str(export)):
        e=_to_xml(e)
        if multi:
            sn=_sensor_of(e); cf=sensor_host.get(sn)
            if cf and not comp(e).startswith(cf): continue
            keyed[sn+":"+rid(e)]=e
        else:
            if cfg.get("computer") and not comp(e).startswith(cfg["computer"]): continue
            keyed[rid(e)]=e
    return keyed, f"Splunk export ({export.name})"

# --------------------------------------------------------------------------- #
#  Build alert_package + selection_metadata from the config
# --------------------------------------------------------------------------- #
def build_package(by_rid, cfg):
    a0 = item(by_rid, "A0", cfg["selection"]["A0"], is_alert=True)
    ev = [item(by_rid,"EV-TMP",r) for r in cfg["selection"]["EV"]]
    ev.sort(key=lambda b:(b["event_time_utc"], b["source_event"]["event_record_id"]))
    for i,b in enumerate(ev,1): b["evidence_id"]=f"EV-{i:03d}"
    allb=[a0]+ev
    ders=[]
    for d in cfg.get("derivations",[]):
        src = a0 if d["from"]=="A0" else next(b for b in ev if b["evidence_id"]==d["from"])
        ders.append({"derivation_id":d["id"],"derived_field":d["as"],
                     "value":DERIVERS[d["method"]](src["attributes"].get(d["field"],"")),
                     "derivation_method":d["note"],"source_evidence_id":d["from"],"source_field":d["field"]})
    users=sorted({b["attributes"].get("user","") or b["attributes"].get("subject_user_name","") for b in allb} - {""})
    times=sorted(b["event_time_utc"] for b in allb)
    pkg={"schema_version":"1.0","case_id":cfg["case_id"],"package_type":"neutral_security_event_package",
      "observed_context":{"computers":sorted({b["computer"] for b in allb if b["computer"]}),"users":users,
        "time_window_utc":{"start":times[0],"end":times[-1]},"event_count":len(allb),
        "event_types_present":sorted({b["event_type"] for b in allb}),
        "sourcetypes_present":cfg["sourcetypes_present"]},
      "main_alert":a0,"evidence_items":ev,"deterministic_derivations":ders}
    pkg = _neut(pkg)          # redact technique-IDs / framework names (allb kept raw for metadata)
    pkg = _redact_model_visible_literals(pkg, cfg)
    pkg = _exclude_model_visible_attributes(pkg, cfg)
    pkg = _anon_hosts(pkg)    # anonymise host/domain ids (uniform across corpora; package hides its source)
    return pkg, allb, times


def _exclude_model_visible_attributes(pkg, cfg):
    """Remove case-configured attributes from specific model-visible evidence items.

    The raw event and selection metadata remain intact. This is for redundant fields whose content leaks
    collection/test-harness context after ordinary token redaction, not for hiding adverse evidence.
    Fail closed if an id or field drifts so an exclusion can never become a silent no-op.
    """
    exclusions = cfg.get("model_visible_attribute_exclusions", {})
    if not exclusions:
        return pkg
    by_id = {pkg["main_alert"]["evidence_id"]: pkg["main_alert"]}
    by_id.update({event["evidence_id"]: event for event in pkg["evidence_items"]})
    for evidence_id, fields in exclusions.items():
        if evidence_id not in by_id:
            raise ValueError(f"unknown model-visible exclusion evidence id: {evidence_id}")
        attributes = by_id[evidence_id]["attributes"]
        for field in fields:
            if field not in attributes:
                raise ValueError(f"model-visible exclusion field absent: {evidence_id}.{field}")
            del attributes[field]
    return pkg

def build_metadata(cfg, allb, times, case_dir):
    ridrole=cfg.get("roles",{})
    multi = "sources" in cfg
    idmap={}
    for b in allb:
        r=b["source_event"]["event_record_id"]
        # Multi-source selections already retain sensor-qualified ids (for example
        # ``sysmon:7134``). Do not qualify them a second time when resolving roles.
        key=_role_lookup_key(r, b["source_event"]["channel"], multi)
        role_note=ridrole.get(key) or f"additional correlated {b['event_type']} event retained by the fixed selection"
        idmap[b["evidence_id"]]={"event_record_id":r,"event_type":b["event_type"],
            "source":b["source_event"]["channel"],"role_note":role_note}
    m=cfg.get("metadata",{})
    first_src = cfg.get("source_log") or cfg.get("mordor_log") or cfg["sources"][0].get("source_log","")
    qref = ("build/case.json" if "mordor_log" in cfg else "queries/" + "retrieval_spec.md")   # mordor's "query" IS case.json
    return {"schema_version":"1.0","case_id":cfg["case_id"],"case_name":m.get("case_name",""),
      "security_proposition":m.get("security_proposition",""),
      "case_directory":m.get("case_directory",""),"split":cfg["split"],"status":m.get("status","curated_draft"),
      "attack_category":m.get("attack_category",{"category":"","candidate_attack_mapping":"","model_visible":False}),
      "source_provenance":{"dataset":m.get("dataset","Splunk Attack Data"),
        "original_repository_path":first_src.replace("attack_data-master/",""),
        "original_filename":Path(first_src).name,"stored_filename":m.get("stored_filename",""),
        "renamed_for_splunk_disambiguation":True,"source_file_sha256":sha256(_resolve_source(cfg,case_dir,first_src)),
        "sources":([{"sensor":s.get("sensor"),"path":(s.get("source_log") or cfg.get("mordor_log","")).replace("attack_data-master/",""),
          "sha256":sha256(_resolve_source(cfg,case_dir,s.get("source_log") or cfg.get("mordor_log","")))} for s in cfg["sources"]] if "sources" in cfg else None),
        "tier":m.get("tier",{}),"splunk":m.get("splunk",{})},
      "case_files":{"source_log":"source/provenance.json","main_alert":cfg.get("staged_export",""),
        "related_events":cfg.get("staged_export",""),"alert_package":"model_input/alert_package.json",
        "ground_truth":"annotations/ground_truth.json",
        "main_alert_query":qref,"related_events_query":qref,
        "selection_metadata":"annotations/selection_metadata.json"},
      "case_scope":{**m.get("case_scope",{}),"time_window_utc":{"start":times[0],"end":times[-1]}},
      "main_alert_selection":{**m.get("main_alert_selection",{}),"event_record_id":cfg["selection"]["A0"],
        "process_guid":allb[0]["attributes"].get("process_guid",""),"query_file":qref},
      "related_event_selection":{"query_file":qref,"main_alert_excluded_from_related_events":True,
        "correlation_keys":m.get("correlation_keys",["ProcessGuid","ParentProcessGuid","host","time_window"]),
        "included_event_record_ids":[cfg["selection"]["A0"]]+cfg["selection"]["EV"],
        "event_groups":m.get("event_groups",[])},
      "evidence_id_map":idmap,"curation_notes":m.get("curation_notes",[]),
      "model_input_controls":{"neutral_case_id_allowed":True,
        "researcher_fields_to_exclude":["alert_name","alert_reason","mitre_technique","evidence_role","split","severity","verdict","ground_truth","evidence_condition"],
        "preprocessing_required":["strip XML entities","repair documented source-encoding artifacts","project raw fields to neutral attributes","assign A0/EV ids"],
        "case_attribute_exclusions":cfg.get("model_visible_attribute_exclusions",{}),
        "case_literal_redactions":cfg.get("model_visible_literal_redactions",{})},
      "experimental_role":m.get("experimental_role",{"used_for":[],"eligible_for_final_heldout_metrics":False}),
      "versioning":{"metadata_version":"1.0","created_date":m.get("created_date","2026-07-05"),"review_status":m.get("review_status","ground_truth_reviewed")},
      "review_required":m.get("review_required",{"ground_truth":"Ground truth reviewed under benchmark rubric v1.1."})}

# --------------------------------------------------------------------------- #
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--from-splunk", default=None)
    ap.add_argument("--from-log", action="store_true")
    ap.add_argument("--verify-log", action="store_true")
    a=ap.parse_args()
    case_dir=Path(a.case).resolve()
    cfg=json.loads((case_dir/"build"/"case.json").read_text())
    # mordor cases skip Splunk, so they have no queries/ (SPL) or extracted/ (staged export) folders
    _dirs = ["source","model_input","annotations","build"] + ([] if "mordor_log" in cfg else ["queries","extracted"])
    for s in _dirs:
        (case_dir/s).mkdir(parents=True, exist_ok=True)
    mode = "verify" if a.verify_log else ("log" if a.from_log else "splunk")
    by_key, desc = load_events(cfg, case_dir, mode, a.from_splunk)
    pkg, allb, times = build_package(by_key, cfg)
    pkg_json=json.dumps(pkg, indent=2, ensure_ascii=False)
    PKG=case_dir/"model_input"/"alert_package.json"

    if a.verify_log:
        ok = PKG.exists() and pkg_json==PKG.read_text(encoding="utf-8")
        print(f"[{cfg['case_id']}] VERIFY ({desc}): "+("MATCH ✅" if ok else "DIFFER ❌")); sys.exit(0 if ok else 1)

    meta=build_metadata(cfg, allb, times, case_dir)
    _srcs = cfg.get("sources") or [{"sensor":"single","source_log":cfg.get("source_log") or cfg.get("mordor_log")}]
    provenance={
        "dataset":cfg.get("metadata",{}).get("dataset","Splunk Attack Data"),
        "sources":[{"sensor":s.get("sensor"),"source_log":s.get("source_log") or cfg.get("mordor_log"),"sha256":sha256(_resolve_source(cfg,case_dir,s.get("source_log") or cfg.get("mordor_log")))} for s in _srcs],
        "primary_host":cfg.get("metadata",{}).get("case_scope",{}).get("primary_host",""),
        "tier":cfg.get("metadata",{}).get("tier",{})}
    (case_dir/"source"/"provenance.json").write_text(json.dumps(provenance,indent=2), encoding="utf-8")
    PKG.write_text(pkg_json, encoding="utf-8")
    (case_dir/"annotations"/"selection_metadata.json").write_text(json.dumps(meta,indent=2,ensure_ascii=False), encoding="utf-8")

    print(f"[{cfg['case_id']}] built from {desc}: A0 + {len(allb)-1} EV + {len(pkg['deterministic_derivations'])} DER")
    try:
        import jsonschema
        for nm,inst,sc in [
            ("case_config",cfg,"case_config.schema.json"),
            ("alert_package",pkg,"alert_package.schema.json"),
            ("selection_metadata",meta,"selection_metadata.schema.json"),
            ("provenance",provenance,"provenance.schema.json"),
        ]:
            try: jsonschema.validate(inst,json.loads((SCH/sc).read_text())); v="PASS"
            except jsonschema.ValidationError as ex: v=f"FAIL: {ex.message[:120]}"
            print(f"    schema {nm:18s} {v}")
    except ModuleNotFoundError:
        print("    schema validation      SKIPPED (jsonschema not installed in this interpreter)")

if __name__=="__main__":
    main()
