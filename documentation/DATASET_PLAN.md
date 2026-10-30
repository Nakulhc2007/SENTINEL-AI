# SENTINEL-AI — Dataset Plan
**Purpose:** Identify training, testing, and simulation datasets for all eight security domains  
**Strategy:** Use real-world public cybersecurity datasets for training the Analyst agent's ML models. Use synthetic log generators for domain-specific UI demonstration.

---

## Dataset Strategy Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    DATA PIPELINE                            │
│                                                             │
│  Real Datasets          Synthetic Generator                 │
│  (for ML model         (for UI demo &                       │
│   training)             hackathon demo)                     │
│      │                       │                              │
│      └──────────┬────────────┘                              │
│                 ▼                                           │
│         Sentinel-Parser (normalization)                     │
│                 ▼                                           │
│         Sentinel-Analyst (detection)                        │
└─────────────────────────────────────────────────────────────┘
```

For the **hackathon demo**, synthetic log generation is used so the team isn't dependent on download times. For the **ML model**, pre-processed samples from the datasets below are embedded.

---

## Domain 1: Network Security

### Dataset: CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Contents:** ~2.8M records — benign traffic + 14 attack types (DDoS, PortScan, Bot, Infiltration, Web Attacks, Brute Force)
- **Format:** CSV with 78 network-flow features (src/dst IP, port, protocol, packet stats)
- **Official Source:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Direct Download:** https://www.kaggle.com/datasets/cicdataset/cicids2017
- **Size:** ~8.7 GB (full) | Pre-processed sample: ~200 MB
- **License:** Research use

### Dataset: CIC-IDS2018 (Updated)
- **Contents:** ~16M records — adds more realistic attack scenarios
- **Official Source:** https://www.unb.ca/cic/datasets/ids-2018.html
- **AWS Open Data:** `s3://cse-cic-ids2018/` (public bucket)
- **Size:** ~100 GB (use sample subset)

### Synthetic Generator for Demo
```python
# domains/network/synthetic_generator.py
# Generates: firewall logs, IDS alerts, NetFlow records
# Attack types: DDoS burst, port scan sequence, lateral movement
```

---

## Domain 2: Endpoint Security

### Dataset: Windows Sysmon Logs (OTRF Security Datasets)
- **Contents:** Structured Sysmon Event IDs (1, 3, 7, 8, 10, 11, 13) from attack simulations including APT29, Cobalt Strike, Mimikatz
- **Official Source:** https://securitydatasets.com/
- **GitHub:** https://github.com/OTRF/Security-Datasets
- **Format:** JSON (Sysmon XML converted), EVTX
- **Size:** Varies by scenario (50 MB–2 GB per simulation)
- **License:** MIT / CC BY 4.0

### Dataset: ADFA Intrusion Detection Dataset (UNSW)
- **Contents:** Linux/Windows system call traces — normal + 6 attack types
- **Official Source:** https://research.unsw.edu.au/projects/adfa-ids-datasets
- **Format:** Text files (syscall sequences)
- **License:** Research use

### Synthetic Generator for Demo
```python
# domains/endpoint/synthetic_generator.py
# Generates: process creation events, file modification events
# Attack types: malware execution, privilege escalation, persistence
```

---

## Domain 3: Cloud Infrastructure

### Dataset: CloudTrail Attack Scenarios (flaws.cloud / CloudGoat)
- **Contents:** AWS CloudTrail JSON logs from intentionally vulnerable cloud environments (privilege escalation, S3 bucket enumeration, IAM abuse)
- **Official Source (CloudGoat):** https://github.com/RhinoSecurityLabs/cloudgoat
- **Official Source (flaws.cloud):** http://flaws.cloud/
- **Format:** AWS CloudTrail JSON format
- **License:** Open source / Educational

### Dataset: BETH Dataset (Behaviour Event Telemetry Hackathon)
- **Contents:** ~8M host events from cloud infrastructure with labeled attacks
- **Official Source:** https://www.kaggle.com/datasets/katehighnam/beth-dataset
- **Format:** CSV
- **License:** CC BY-NC-SA 4.0

### Synthetic Generator for Demo
```python
# domains/cloud/synthetic_generator.py
# Generates: CloudTrail-format JSON logs
# Attack types: IAM privilege escalation, S3 data exfiltration, Lambda abuse
```

---

## Domain 4: Identity & Access Management (IAM)

### Dataset: LANL Unified Host and Network Dataset
- **Contents:** 58 days of authentication, process, network, and DNS events from Los Alamos National Lab
- **Official Source:** https://csr.lanl.gov/data/unified-host-network-dataset-2017/
- **Format:** CSV/gzip
- **Size:** ~12 GB (compressed)
- **License:** Open for research

### Dataset: UNM User Commands Dataset
- **Contents:** Unix shell commands from 70 users — used for insider threat / behavioral analysis
- **Official Source:** https://www.cs.unm.edu/~immsec/systemcalls.htm
- **Format:** Text files per user

### Synthetic Generator for Demo
```python
# domains/iam/synthetic_generator.py
# Generates: LDAP auth logs, VPN access logs
# Attack types: brute force, impossible travel, MFA bypass attempts
```

---

## Domain 5: Application Security

### Dataset: OWASP WebGoat + Juice Shop Logs
- **Contents:** WAF and access logs from intentionally vulnerable web applications (OWASP Top 10 attacks)
- **Official Source:** https://owasp.org/www-project-webgoat/
- **Format:** Apache/Nginx access log format + WAF alert JSON
- **License:** Open source (Apache 2.0)

### Dataset: SecRepo WAF Logs
- **Contents:** Real anonymized WAF logs with SQLi, XSS, LFI, RFI attack patterns
- **Official Source:** https://www.secrepo.com/
- **License:** Creative Commons

### Dataset: CSIC 2010 HTTP Dataset (Application Layer)
- **Contents:** 36,000+ web requests labeled normal/anomalous (SQLi, Buffer Overflow, XSS)
- **Official Source:** https://www.isi.csic.es/dataset/
- **Format:** HTTP request logs

### Synthetic Generator for Demo
```python
# domains/appsec/synthetic_generator.py
# Generates: WAF logs, API gateway logs
# Attack types: SQLi patterns, XSS payloads, auth bypass attempts
```

---

## Domain 6: Data Loss Prevention (DLP)

### Dataset: CERT Insider Threat (includes DLP scenarios)
- **Contents:** Detailed synthetic logs of 1000 employees over 18 months — includes USB device events, email exfiltration, large file transfers
- **Official Source:** https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099
- **GitHub:** https://github.com/szydkp/CERT-Insider-Threat-Dataset
- **Format:** CSV (device, logon, email, http, file activity logs)
- **License:** Free for research

### Synthetic Generator for Demo
```python
# domains/dlp/synthetic_generator.py
# Generates: USB device logs, email attachment logs, cloud upload logs
# Attack types: mass data download, unauthorized USB transfer, email exfiltration
```

---

## Domain 7: Insider Threat

### Dataset: CERT Insider Threat Test Dataset v6.2 (Primary)
- **Contents:** Synthetic but realistic — 70 insider threat scenarios including malicious/non-malicious employees. Includes logon, device, email, file, and HTTP activity logs.
- **Official Source:** https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099
- **CERT Portal:** https://www.sei.cmu.edu/research-capabilities/all-work/display.cfm?customel_datapageid_4050=21274
- **Format:** CSV (6 separate activity files + answer key)
- **License:** Free — requires registration/agreement

### Dataset: HDFS Log Dataset (Loghub)
- **Contents:** 11M HDFS system logs with labeled anomalies — useful for behavioral baselining
- **Official Source:** https://github.com/logpai/loghub
- **Format:** Raw log text + structured CSV

### Synthetic Generator for Demo
```python
# domains/insider/synthetic_generator.py
# Generates: UEBA-format events, badge access logs
# Attack types: after-hours access, data hoarding, credential misuse
```

---

## Domain 8: Compliance & Governance

> This domain does not require a training dataset. Instead, it uses rule-based compliance mapping based on:
- **GDPR Article Index** (https://gdpr-info.eu/)
- **HIPAA Security Rule Matrix** (https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- **SOC 2 Trust Service Criteria** (https://www.aicpa.org/)
- **ISO 27001:2022 Controls** (https://www.iso.org/standard/27001)
- **NIST CSF 2.0** (https://www.nist.gov/cyberframework)

The Auditor agent uses a JSON-based compliance rule mapping file that maps incident types to applicable regulatory controls.

---

## Synthetic Log Generator (Cross-Domain Demo Tool)

For the **hackathon demo**, we build a `synthetic_log_generator.py` module that:

```python
# Located at: backend/synthetic/generator.py

class SyntheticLogGenerator:
    """
    Generates realistic security logs for any of the 8 domains.
    Used for demo when real log files are not uploaded.
    """
    def generate(self, domain: str, num_events: int = 100, 
                 attack_type: str = "random") -> list[dict]:
        ...

# Supported domains:
DOMAINS = [
    "network_security",
    "endpoint_security", 
    "cloud_infrastructure",
    "iam",
    "application_security",
    "dlp",
    "insider_threat",
    "compliance"
]

# Each generator injects a configurable % of anomalous events
# Default: 15% anomalous, 85% benign (realistic ratio)
```

---

## Dataset Download Checklist

| Domain | Dataset | Status | Size | Priority |
|--------|---------|--------|------|----------|
| Network | CIC-IDS2017 (sample) | ⬜ To Download | 200 MB | High |
| Endpoint | OTRF Sysmon (APT29 scenario) | ⬜ To Download | 150 MB | High |
| Cloud | CloudGoat (CloudTrail JSONs) | ⬜ To Download | 50 MB | Medium |
| IAM | LANL (sample subset) | ⬜ To Download | 500 MB | Medium |
| AppSec | CSIC 2010 HTTP | ⬜ To Download | 30 MB | High |
| DLP | CERT Insider v6.2 | ⬜ To Download | 80 MB | High |
| Insider | CERT Insider v6.2 (same) | ⬜ Shared | — | High |
| Compliance | Rule files (hand-crafted) | ✅ Built-in | <1 MB | Done |

> **Note:** For the Analyst agent's anomaly detection model, we pre-train on sampled subsets (10–20% of full dataset) to keep training time under 30 minutes on a typical laptop.
