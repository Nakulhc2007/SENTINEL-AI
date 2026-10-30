"""
SENTINEL-AI — CIC-IDS2017 Preprocessor
========================================
Reads raw CIC-IDS2017 CSV files from data/raw/cicids2017/
Cleans, normalizes, and writes CES records to data/processed/normalized/cicids2017_ces.csv

Key cleaning steps:
  - Strip whitespace from column names (UNB CSVs have leading spaces)
  - Drop Inf / NaN rows
  - Map attack labels → is_attack + attack_type
  - Map to Common Event Schema
  - Preserve original label and all stats in extra_fields

Run: python scripts/dataset_preparation/03_preprocess_cicids2017.py

Output: data/processed/normalized/cicids2017_ces.csv
        data/processed/samples/cicids2017_sample_1k.csv
"""

import sys
import json
import warnings
from pathlib import Path
from datetime import datetime, timezone, timedelta

# ── Resolve project root ──────────────────────────────────────────────────────
ROOT      = Path(__file__).resolve().parents[2]
RAW_DIR   = ROOT / "data" / "raw" / "cicids2017"
NORM_DIR  = ROOT / "data" / "processed" / "normalized"
SAMP_DIR  = ROOT / "data" / "processed" / "samples"
NORM_DIR.mkdir(parents=True, exist_ok=True)
SAMP_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(ROOT / "scripts" / "dataset_preparation"))
from schema import (build_record, CES_COLUMNS, SOURCE_CICIDS2017,
                    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM,
                    SEVERITY_HIGH, SEVERITY_CRITICAL)

warnings.filterwarnings("ignore")


# ── Label mappings ────────────────────────────────────────────────────────────
def map_label(raw_label: str):
    """Return (is_attack, attack_type, severity) from CIC-IDS2017 label."""
    label = raw_label.strip().upper()
    if label == "BENIGN":
        return False, "BENIGN", SEVERITY_INFO
    attack_map = {
        "DDOS":                         ("DDoS",            SEVERITY_CRITICAL),
        "PORTSCAN":                     ("PortScan",         SEVERITY_MEDIUM),
        "BOT":                          ("Bot/C2",           SEVERITY_HIGH),
        "INFILTRATION":                 ("Infiltration",     SEVERITY_HIGH),
        "WEB ATTACK – BRUTE FORCE":     ("BruteForce-Web",  SEVERITY_MEDIUM),
        "WEB ATTACK \x96 BRUTE FORCE":  ("BruteForce-Web",  SEVERITY_MEDIUM),
        "WEB ATTACK – XSS":             ("XSS",             SEVERITY_MEDIUM),
        "WEB ATTACK \x96 XSS":          ("XSS",             SEVERITY_MEDIUM),
        "WEB ATTACK – SQL INJECTION":   ("SQLi",            SEVERITY_HIGH),
        "WEB ATTACK \x96 SQL INJECTION":("SQLi",            SEVERITY_HIGH),
        "FTP-PATATOR":                  ("FTP-BruteForce",  SEVERITY_MEDIUM),
        "SSH-PATATOR":                  ("SSH-BruteForce",  SEVERITY_MEDIUM),
        "DOS GOLDENEYE":                ("DoS-GoldenEye",   SEVERITY_HIGH),
        "DOS HULK":                     ("DoS-Hulk",        SEVERITY_HIGH),
        "DOS SLOWHTTPTEST":             ("DoS-SlowHTTP",    SEVERITY_MEDIUM),
        "DOS SLOWLORIS":                ("DoS-Slowloris",   SEVERITY_MEDIUM),
        "HEARTBLEED":                   ("Heartbleed",      SEVERITY_CRITICAL),
    }
    for key, (atype, sev) in attack_map.items():
        if key in label:
            return True, atype, sev
    return True, raw_label.strip(), SEVERITY_MEDIUM   # fallback


def infer_protocol(proto_id):
    """Map numeric protocol to string."""
    mapping = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "HOPOPT"}
    try:
        return mapping.get(int(float(str(proto_id))), str(proto_id))
    except (ValueError, TypeError):
        return str(proto_id)


def make_raw_log(row) -> str:
    """Build a human-readable raw log string from a CIC-IDS2017 row."""
    return (
        f"[NETFLOW] {row.get('Timestamp','?')} "
        f"src={row.get('Source IP','?')}:{row.get('Source Port','?')} "
        f"dst={row.get('Destination IP','?')}:{row.get('Destination Port','?')} "
        f"proto={infer_protocol(row.get('Protocol','?'))} "
        f"label={row.get('Label','?')}"
    )


def process_file(csv_path: Path, max_rows: int = None) -> list[dict]:
    """Parse one CIC-IDS2017 CSV into a list of CES records."""
    import pandas as pd
    import numpy as np

    print(f"  Reading {csv_path.name} ...", end=" ", flush=True)
    try:
        df = pd.read_csv(csv_path, low_memory=False, encoding="utf-8",
                         on_bad_lines="skip")
    except Exception:
        df = pd.read_csv(csv_path, low_memory=False, encoding="latin-1",
                         on_bad_lines="skip")

    # ── Clean column names (strip leading/trailing whitespace) ──────────────
    df.columns = df.columns.str.strip()
    print(f"shape={df.shape}", end=" ")

    # ── Drop rows with Inf or NaN in numeric columns ─────────────────────────
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(subset=["Label"], inplace=True)
    df.reset_index(drop=True, inplace=True)
    print(f"→ after clean={len(df)} rows (dropped {before - len(df)} Inf/NaN)")

    if max_rows:
        # Stratified sample: preserve benign/attack ratio
        benign = df[df["Label"].str.strip().str.upper() == "BENIGN"]
        attacks = df[df["Label"].str.strip().str.upper() != "BENIGN"]
        n_benign  = min(int(max_rows * 0.7), len(benign))
        n_attacks = min(int(max_rows * 0.3), len(attacks))
        df = pd.concat([
            benign.sample(n=n_benign, random_state=42),
            attacks.sample(n=min(n_attacks, len(attacks)), random_state=42),
        ], ignore_index=True).sample(frac=1, random_state=42)  # shuffle

    records = []
    base_ts  = datetime(2017, 7, 3, 8, 0, 0, tzinfo=timezone.utc)

    for i, row in df.iterrows():
        is_attack, attack_type, severity = map_label(str(row.get("Label", "")))

        raw = make_raw_log(row)

        # Extra fields preserve the original 79 numeric features
        numeric_cols = [c for c in df.columns if c not in
                        ("Source IP", "Destination IP", "Source Port",
                         "Destination Port", "Protocol", "Label", "Timestamp")]
        extra = {c: (None if pd.isna(row.get(c)) else round(float(row.get(c)), 4))
                 for c in numeric_cols[:20]}   # keep top-20 features for size
        extra["original_label"] = row.get("Label", "?")

        # Parse timestamp if present
        ts_str = str(row.get("Timestamp", "")).strip()
        try:
            ts = datetime.strptime(ts_str, "%d/%m/%Y %H:%M")
            ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            ts = base_ts + timedelta(seconds=i)

        rec = build_record(
            domain          = "network_security",
            source_dataset  = SOURCE_CICIDS2017,
            record_type     = "real",
            timestamp       = ts,
            event_type      = "network",
            severity        = severity,
            action          = "block" if is_attack else "allow",
            raw_log         = raw,
            src_ip          = str(row.get("Source IP", "")).strip() or None,
            dst_ip          = str(row.get("Destination IP", "")).strip() or None,
            src_port        = int(row["Source Port"]) if str(row.get("Source Port","")).strip().isdigit() else None,
            dst_port        = int(row["Destination Port"]) if str(row.get("Destination Port","")).strip().isdigit() else None,
            protocol        = infer_protocol(row.get("Protocol")),
            is_attack       = is_attack,
            attack_type     = attack_type if is_attack else None,
            extra_fields    = extra,
        )
        records.append(rec)

    return records


def main():
    import pandas as pd

    print("\n" + "=" * 60)
    print("  CIC-IDS2017 Preprocessor")
    print("=" * 60)

    csv_files = sorted(RAW_DIR.glob("*.csv"))
    if not csv_files:
        print(f"\n[WARN] No CSV files found in {RAW_DIR}")
        print("   Download first: python scripts/dataset_preparation/02_download_datasets.py")
        print("   Or manual: https://www.unb.ca/cic/datasets/ids-2017.html\n")
        return

    all_records = []
    for csv_path in csv_files:
        print(f"\nProcessing: {csv_path.name}")
        recs = process_file(csv_path, max_rows=50000)
        all_records.extend(recs)
        # Per-file label distribution
        labels = {}
        for r in recs:
            k = r["attack_type"] or "BENIGN"
            labels[k] = labels.get(k, 0) + 1
        for k, v in sorted(labels.items(), key=lambda x: -x[1])[:8]:
            print(f"    {k:35s} : {v:6d}")

    print(f"\n  Total CES records: {len(all_records)}")

    # ── Write full normalized CSV ─────────────────────────────────────────────
    out_path = NORM_DIR / "cicids2017_ces.csv"
    df_out = []
    for r in all_records:
        row = {col: r.get(col, "") for col in CES_COLUMNS if col != "extra_fields"}
        row["extra_fields"] = json.dumps(r.get("extra_fields", {}))
        df_out.append(row)
    df_out = pd.DataFrame(df_out, columns=CES_COLUMNS)
    df_out.to_csv(out_path, index=False)
    print(f"\n  ✓ Normalized → {out_path.relative_to(ROOT)} ({out_path.stat().st_size/1024:.1f} KB)")

    # ── Write 1 K sample ─────────────────────────────────────────────────────
    samp = df_out.sample(n=min(1000, len(df_out)), random_state=42)
    samp_path = SAMP_DIR / "cicids2017_sample_1k.csv"
    samp.to_csv(samp_path, index=False)
    print(f"  ✓ Sample    → {samp_path.relative_to(ROOT)}")

    # Summary stats
    total   = len(df_out)
    attacks = (df_out["is_attack"] == True).sum()
    print(f"\n  Records  : {total:,}")
    print(f"  Attacks  : {attacks:,} ({attacks/total*100:.1f}%)")
    print(f"  Benign   : {total - attacks:,} ({(total-attacks)/total*100:.1f}%)")
    print(f"  Severity distribution:")
    for sv, label in {0:"info",1:"low",2:"medium",3:"high",4:"critical"}.items():
        n = (df_out["severity"] == sv).sum()
        print(f"    {label:10s}: {n:,}")


if __name__ == "__main__":
    main()
