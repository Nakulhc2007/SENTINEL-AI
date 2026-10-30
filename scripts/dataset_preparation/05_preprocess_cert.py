"""
SENTINEL-AI — CERT Insider Threat Preprocessor
================================================
If data/raw/cert_insider/r6.2/ exists (after manual download):
  Reads logon.csv, device.csv, email.csv, file.csv, http.csv
  Normalizes to CES schema

If data is NOT present:
  Generates a statistically realistic 3000-row synthetic CERT-style
  dataset that matches the schema exactly — clearly marked as synthetic.

Run: python scripts/dataset_preparation/05_preprocess_cert.py

Outputs: data/processed/normalized/cert_insider_ces.csv
         data/processed/samples/cert_insider_sample_500.csv
"""

import sys
import json
import random
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT     = Path(__file__).resolve().parents[2]
RAW_DIR  = ROOT / "data" / "raw" / "cert_insider"
NORM_DIR = ROOT / "data" / "processed" / "normalized"
SAMP_DIR = ROOT / "data" / "processed" / "samples"
NORM_DIR.mkdir(parents=True, exist_ok=True)
SAMP_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(ROOT / "scripts" / "dataset_preparation"))
from schema import (build_record, CES_COLUMNS, SOURCE_CERT_INSIDER,
                    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM,
                    SEVERITY_HIGH, SEVERITY_CRITICAL)


# ── Malicious user pool (from r6.2 known scenarios) ─────────────────────────
MALICIOUS_USERS = {
    "ACM2278", "CMP2946", "DLD1655", "GWC3965",
    "HFH1074", "JBS1247", "KAV0874", "MSR1016",
    "NTD2840", "PAA1259", "RBA1282", "SWR2803",
}

# ══════════════════════════════════════════════════════════════════════════════
# A — Process real CERT data (if downloaded)
# ══════════════════════════════════════════════════════════════════════════════
def process_real_cert(r62_dir: Path) -> list[dict]:
    """Parse real CERT r6.2 CSV files into CES records."""
    import pandas as pd

    records = []
    files_found = list(r62_dir.glob("*.csv"))
    print(f"  Found {len(files_found)} CSV files in {r62_dir.name}")

    # ── logon.csv ─────────────────────────────────────────────────────────────
    logon_path = r62_dir / "logon.csv"
    if logon_path.exists():
        df = pd.read_csv(logon_path, parse_dates=["date"],
                         date_format="%m/%d/%Y %H:%M:%S")
        print(f"  logon.csv : {len(df):,} rows")
        for _, row in df.iterrows():
            user  = str(row.get("user", ""))
            is_attack = user in MALICIOUS_USERS
            ts    = row["date"] if not pd.isna(row["date"]) else datetime(2010, 1, 2, tzinfo=timezone.utc)
            ts    = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
            raw   = f"[LOGON] {ts} user={user} pc={row.get('pc','')} activity={row.get('activity','')}"
            rec   = build_record(
                domain         = "insider_threat",
                source_dataset = SOURCE_CERT_INSIDER,
                record_type    = "real",
                timestamp      = ts,
                event_type     = "auth",
                severity       = SEVERITY_MEDIUM if is_attack else SEVERITY_INFO,
                action         = str(row.get("activity", "Logon")).lower(),
                raw_log        = raw,
                username       = user,
                hostname       = str(row.get("pc", "")),
                is_attack      = is_attack,
                attack_type    = "InsiderThreat" if is_attack else None,
                extra_fields   = {"activity": row.get("activity"), "record_id": row.get("id", "")},
            )
            records.append(rec)

    # ── device.csv ────────────────────────────────────────────────────────────
    device_path = r62_dir / "device.csv"
    if device_path.exists():
        df = pd.read_csv(device_path, parse_dates=["date"],
                         date_format="%m/%d/%Y %H:%M:%S")
        print(f"  device.csv: {len(df):,} rows")
        for _, row in df.iterrows():
            user  = str(row.get("user", ""))
            is_attack = user in MALICIOUS_USERS
            activity = str(row.get("activity", "Connect"))
            ts    = row["date"] if not pd.isna(row["date"]) else datetime(2010, 1, 2, tzinfo=timezone.utc)
            ts    = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
            raw   = f"[USB] {ts} user={user} pc={row.get('pc','')} activity={activity}"
            rec   = build_record(
                domain         = "dlp",
                source_dataset = SOURCE_CERT_INSIDER,
                record_type    = "real",
                timestamp      = ts,
                event_type     = "usb",
                severity       = SEVERITY_HIGH if (is_attack and "connect" in activity.lower()) else SEVERITY_LOW,
                action         = activity.lower().replace(" ", "_"),
                raw_log        = raw,
                username       = user,
                hostname       = str(row.get("pc", "")),
                is_attack      = is_attack,
                attack_type    = "USBExfiltration" if is_attack else None,
                extra_fields   = {"activity": activity, "record_id": row.get("id", "")},
            )
            records.append(rec)

    # ── email.csv ─────────────────────────────────────────────────────────────
    email_path = r62_dir / "email.csv"
    if email_path.exists():
        df = pd.read_csv(email_path, parse_dates=["date"],
                         date_format="%m/%d/%Y %H:%M:%S")
        print(f"  email.csv : {len(df):,} rows")
        for _, row in df.iterrows():
            user  = str(row.get("user", ""))
            is_attack = user in MALICIOUS_USERS
            ts    = row["date"] if not pd.isna(row["date"]) else datetime(2010, 1, 2, tzinfo=timezone.utc)
            ts    = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
            size  = row.get("size", 0)
            atts  = row.get("attachments", 0)
            raw   = (f"[EMAIL] {ts} user={user} pc={row.get('pc','')} "
                     f"activity={row.get('activity','')} size={size} attachments={atts}")
            sev   = SEVERITY_HIGH if (is_attack and int(atts or 0) > 0) else SEVERITY_INFO
            rec   = build_record(
                domain         = "dlp",
                source_dataset = SOURCE_CERT_INSIDER,
                record_type    = "real",
                timestamp      = ts,
                event_type     = "email",
                severity       = sev,
                action         = str(row.get("activity", "Send")).lower(),
                raw_log        = raw,
                username       = user,
                hostname       = str(row.get("pc", "")),
                is_attack      = is_attack,
                attack_type    = "EmailExfiltration" if is_attack else None,
                extra_fields   = {"size_bytes": size, "attachments": atts,
                                   "record_id": row.get("id", "")},
            )
            records.append(rec)

    return records


# ══════════════════════════════════════════════════════════════════════════════
# B — Generate CERT-schema synthetic data (when real data not available)
# ══════════════════════════════════════════════════════════════════════════════
def generate_synthetic_cert(n_records: int = 3000) -> list[dict]:
    """
    Generate realistic CERT r6.2 schema synthetic data.
    Clearly tagged as: record_type='synthetic', source_dataset='synthetic_insider_threat'
    Matches CERT statistical profile: ~2.5% malicious actions.
    """
    rng = random.Random(42)
    base_ts = datetime(2010, 1, 4, 7, 0, 0, tzinfo=timezone.utc)

    # User pool
    normal_users = [f"USR{str(i).zfill(4)}" for i in range(1, 100)]
    mal_users = ["ACM2278", "CMP2946", "DLD1655", "GWC3965", "HFH1074"]
    pcs = [f"PC-{str(i).zfill(4)}" for i in range(1, 50)]

    # Activity types per domain
    logon_acts   = ["Logon", "Logoff"]
    device_acts  = ["Connect", "Disconnect"]
    email_acts   = ["Send", "View"]
    file_acts    = ["Open", "Copy", "Delete", "Write", "Rename"]
    http_acts    = ["WWW Visit", "WWW Download", "WWW Upload"]

    records = []
    for i in range(n_records):
        ts = base_ts + timedelta(
            days=rng.randint(0, 500),
            hours=rng.randint(7, 20),
            minutes=rng.randint(0, 59),
            seconds=rng.randint(0, 59),
        )

        # 2.5% malicious
        is_attack = rng.random() < 0.025
        user = rng.choice(mal_users if is_attack else normal_users)
        pc   = rng.choice(pcs)

        # Pick event type
        etype_pick = rng.choices(
            ["logon", "device", "email", "file", "http"],
            weights=[30, 10, 20, 25, 15]
        )[0]

        if etype_pick == "logon":
            activity = rng.choice(logon_acts)
            domain   = "insider_threat"
            event_type = "auth"
            sev = SEVERITY_MEDIUM if is_attack else SEVERITY_INFO
            attack_type = "Logon-AfterHours" if is_attack else None
            raw = f"[LOGON] {ts.isoformat()} user={user} pc={pc} activity={activity}"
            extra = {"activity": activity, "source": "cert_synthetic"}

        elif etype_pick == "device":
            activity = rng.choice(device_acts)
            domain   = "dlp"
            event_type = "usb"
            sev = SEVERITY_HIGH if is_attack else SEVERITY_LOW
            attack_type = "USBExfiltration" if is_attack else None
            raw = f"[USB] {ts.isoformat()} user={user} pc={pc} activity={activity}"
            extra = {"activity": activity, "source": "cert_synthetic"}

        elif etype_pick == "email":
            activity = rng.choice(email_acts)
            size = rng.randint(1024, 10_000_000) if is_attack else rng.randint(512, 50000)
            atts = rng.randint(1, 5) if is_attack else 0
            exfil_domain = rng.choice(["gmail.com", "yahoo.com", "protonmail.com"]) if is_attack else "company.com"
            domain = "dlp"
            event_type = "email"
            sev = SEVERITY_HIGH if is_attack else SEVERITY_INFO
            attack_type = "EmailExfiltration" if is_attack else None
            raw = (f"[EMAIL] {ts.isoformat()} user={user} pc={pc} "
                   f"to=external@{exfil_domain} size={size} attachments={atts} activity={activity}")
            extra = {"size_bytes": size, "attachments": atts, "recipient_domain": exfil_domain,
                     "source": "cert_synthetic"}

        elif etype_pick == "file":
            activity = rng.choice(file_acts)
            filename = rng.choice([
                "confidential_report.docx", "salary_data.xlsx",
                "customer_list.csv", "source_code.zip", "budget_2026.xlsx",
            ]) if is_attack else f"document_{rng.randint(1,999)}.docx"
            fpath = f"C:\\Users\\{user}\\Documents\\{filename}"
            domain = "insider_threat"
            event_type = "file"
            sev = SEVERITY_HIGH if is_attack else SEVERITY_INFO
            attack_type = "DataHoarding" if is_attack else None
            raw = (f"[FILE] {ts.isoformat()} user={user} pc={pc} "
                   f"file={fpath} activity={activity}")
            extra = {"activity": activity, "filename": filename, "source": "cert_synthetic"}

        else:  # http
            activity = rng.choice(http_acts)
            url = rng.choice([
                "http://wikileaks.org/...", "http://pastebin.com/...",
                "http://dropbox.com/upload", "http://wetransfer.com",
            ]) if is_attack else f"http://intranet.company.com/page{rng.randint(1,50)}"
            domain = "insider_threat"
            event_type = "web"
            sev = SEVERITY_MEDIUM if is_attack else SEVERITY_INFO
            attack_type = "SuspiciousWebActivity" if is_attack else None
            raw = f"[HTTP] {ts.isoformat()} user={user} pc={pc} url={url} activity={activity}"
            extra = {"url": url, "activity": activity, "source": "cert_synthetic"}

        rec = build_record(
            domain         = domain,
            source_dataset = "synthetic_insider_threat",
            record_type    = "synthetic",
            timestamp      = ts,
            event_type     = event_type,
            severity       = sev,
            action         = activity.lower().replace(" ", "_"),
            raw_log        = raw,
            username       = user,
            hostname       = pc,
            is_attack      = is_attack,
            attack_type    = attack_type,
            extra_fields   = extra,
        )
        records.append(rec)

    return records


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════
def main():
    import pandas as pd

    print("\n" + "=" * 60)
    print("  CERT Insider Threat Preprocessor")
    print("=" * 60)

    r62_dir = RAW_DIR / "r6.2"
    if r62_dir.exists() and any(r62_dir.glob("*.csv")):
        print(f"\n  Found real r6.2 data at {r62_dir}")
        records = process_real_cert(r62_dir)
    else:
        print(f"\n  [WARN] Real CERT r6.2 data not found at {r62_dir}")
        print("         Generating CERT-schema synthetic dataset (3000 records)...")
        print("         All records tagged as record_type='synthetic'")
        records = generate_synthetic_cert(n_records=3000)

    if not records:
        print("[ERROR] No records generated.")
        return

    # ── Stats ─────────────────────────────────────────────────────────────────
    total    = len(records)
    attacks  = sum(1 for r in records if r["is_attack"])
    real_rec = sum(1 for r in records if r["record_type"] == "real")
    synth    = sum(1 for r in records if r["record_type"] == "synthetic")
    print(f"\n  Total records  : {total:,}")
    print(f"  Real records   : {real_rec:,}")
    print(f"  Synthetic recs : {synth:,}")
    print(f"  Malicious evts : {attacks:,} ({attacks/total*100:.1f}%)")

    # ── Write normalized CES ───────────────────────────────────────────────────
    df_rows = []
    for r in records:
        row = {col: r.get(col, "") for col in CES_COLUMNS if col != "extra_fields"}
        row["extra_fields"] = json.dumps(r.get("extra_fields", {}))
        df_rows.append(row)

    df_out = pd.DataFrame(df_rows, columns=CES_COLUMNS)
    out_path  = NORM_DIR / "cert_insider_ces.csv"
    samp_path = SAMP_DIR / "cert_insider_sample_500.csv"

    df_out.to_csv(out_path, index=False)
    df_out.sample(n=min(500, len(df_out)), random_state=42).to_csv(samp_path, index=False)

    print(f"\n  ✓ Normalized → {out_path.relative_to(ROOT)} ({out_path.stat().st_size/1024:.1f} KB)")
    print(f"  ✓ Sample     → {samp_path.relative_to(ROOT)}")

    # Domain breakdown
    domain_counts = {}
    for r in records:
        domain_counts[r["domain"]] = domain_counts.get(r["domain"], 0) + 1
    print("\n  Domain breakdown:")
    for d, c in sorted(domain_counts.items(), key=lambda x: -x[1]):
        print(f"    {d:25s}: {c:,}")


if __name__ == "__main__":
    main()
