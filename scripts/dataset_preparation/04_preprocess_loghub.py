"""
SENTINEL-AI — LogHub HDFS Preprocessor
=========================================
Reads data/raw/loghub/HDFS_sample_5k.log (line-by-line HDFS logs)
Parses log structure, infers anomaly from label embedded during generation,
and writes CES records to data/processed/normalized/loghub_hdfs_ces.csv

If the full HDFS_1.log is present (1.5 GB), processes first N lines of it.

Run: python scripts/dataset_preparation/04_preprocess_loghub.py

Output: data/processed/normalized/loghub_hdfs_ces.csv
        data/processed/samples/loghub_hdfs_sample_500.csv
"""

import re
import sys
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT     = Path(__file__).resolve().parents[2]
RAW_DIR  = ROOT / "data" / "raw" / "loghub"
NORM_DIR = ROOT / "data" / "processed" / "normalized"
SAMP_DIR = ROOT / "data" / "processed" / "samples"
NORM_DIR.mkdir(parents=True, exist_ok=True)
SAMP_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(ROOT / "scripts" / "dataset_preparation"))
from schema import (build_record, CES_COLUMNS, SOURCE_LOGHUB_HDFS,
                    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM,
                    SEVERITY_HIGH, SEVERITY_CRITICAL)


# ── HDFS log regex ─────────────────────────────────────────────────────────────
# Format: DDMMYY HHMMSS PID LEVEL COMPONENT: CONTENT
# Example: 081109 203615 148 INFO dfs.DataBlock: writeBlock blk_-123 ...
HDFS_PATTERN = re.compile(
    r"^(?P<date>\d{6})\s+"
    r"(?P<time>\d{6})\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<level>\w+)\s+"
    r"(?P<component>\S+):\s*"
    r"(?P<content>.+)$"
)

# Anomaly keywords to infer label if not embedded
ANOMALY_KEYWORDS = [
    "exception", "error", "failed", "timeout", "unreachable",
    "IOException", "SocketException", "SocketTimeoutException",
    "timed out", "Unexpected error", "BlockInfo not found",
]

def classify_hdfs_line(content: str, component: str, level: str):
    """Return (is_attack, attack_type, severity, event_type)."""
    content_lower = content.lower()
    level_upper = level.upper()

    # Check if our generator embedded ANOMALY label in component
    is_anomaly_embedded = "ANOMALY" in component.upper()

    is_anomaly = is_anomaly_embedded or any(
        kw.lower() in content_lower for kw in ANOMALY_KEYWORDS
    )

    if level_upper in ("ERROR", "FATAL") or is_anomaly:
        severity = SEVERITY_HIGH if "exception" in content_lower else SEVERITY_MEDIUM
    else:
        severity = SEVERITY_INFO

    # Determine sub-type
    if "exception" in content_lower or "error" in content_lower:
        attack_type = "DataNode-Exception"
    elif "timeout" in content_lower or "timed out" in content_lower:
        attack_type = "Replication-Timeout"
    elif "failed" in content_lower:
        attack_type = "Block-TransferFailed"
    else:
        attack_type = None

    return is_anomaly, attack_type, severity


def parse_hdfs_timestamp(date_str: str, time_str: str) -> datetime:
    """Parse DDMMYY HHMMSS into datetime."""
    try:
        dt_str = date_str + time_str
        return datetime.strptime(dt_str, "%d%m%y%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime(2011, 11, 8, tzinfo=timezone.utc)


def extract_block_id(content: str) -> str | None:
    """Extract HDFS block ID from log content."""
    m = re.search(r"blk_(-?\d+)", content)
    return m.group(1) if m else None


def extract_ip(content: str) -> str | None:
    """Extract first IP-like pattern from content."""
    m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", content)
    return m.group(1) if m else None


def process_hdfs_log(log_path: Path, max_lines: int = 20000) -> list[dict]:
    """Parse HDFS log file into CES records."""
    print(f"  Reading {log_path.name} ...", end=" ", flush=True)
    records = []
    skipped = 0

    with open(log_path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            line = line.rstrip()
            if not line:
                continue

            m = HDFS_PATTERN.match(line)
            if not m:
                skipped += 1
                continue

            date_s    = m.group("date")
            time_s    = m.group("time")
            pid       = m.group("pid")
            level     = m.group("level")
            component = m.group("component")
            content   = m.group("content")

            ts        = parse_hdfs_timestamp(date_s, time_s)
            block_id  = extract_block_id(content)
            src_ip    = extract_ip(content)

            is_anomaly, attack_type, severity = classify_hdfs_line(
                content, component, level)

            raw_log = line

            rec = build_record(
                domain          = "endpoint_security",
                source_dataset  = SOURCE_LOGHUB_HDFS,
                record_type     = "real",
                timestamp       = ts,
                event_type      = "process",
                severity        = severity,
                action          = "error" if is_anomaly else "success",
                raw_log         = raw_log,
                src_ip          = src_ip,
                hostname        = f"datanode-{pid[-3:]}",
                process_name    = "HDFS-DataNode",
                is_attack       = is_anomaly,
                attack_type     = attack_type,
                extra_fields    = {
                    "pid":        pid,
                    "log_level":  level,
                    "component":  component.replace("NORMAL:", "").replace("ANOMALY:", ""),
                    "block_id":   block_id,
                    "hdfs_content": content[:200],
                },
            )
            records.append(rec)

    print(f"{len(records)} records parsed ({skipped} skipped lines)")
    return records


def main():
    import pandas as pd

    print("\n" + "=" * 60)
    print("  LogHub HDFS Preprocessor")
    print("=" * 60)

    # Prefer full log if available, otherwise use sample
    full_log_path   = RAW_DIR / "HDFS_1.log"
    sample_log_path = RAW_DIR / "HDFS_sample_5k.log"

    if full_log_path.exists():
        log_path  = full_log_path
        max_lines = 100000
        print(f"  Using full HDFS_1.log (processing first {max_lines:,} lines)")
    elif sample_log_path.exists():
        log_path  = sample_log_path
        max_lines = 20000
        print(f"  Using generated sample: {sample_log_path.name}")
    else:
        print(f"\n[WARN] No HDFS log found in {RAW_DIR}")
        print("   Run: python scripts/dataset_preparation/02_download_datasets.py")
        return

    records = process_hdfs_log(log_path, max_lines=max_lines)

    if not records:
        print("[ERROR] No records parsed.")
        return

    total    = len(records)
    anomalies= sum(1 for r in records if r["is_attack"])
    print(f"\n  Total records : {total:,}")
    print(f"  Anomalies     : {anomalies:,} ({anomalies/total*100:.1f}%)")
    print(f"  Normal        : {total - anomalies:,} ({(total-anomalies)/total*100:.1f}%)")

    # ── Write normalized CES CSV ───────────────────────────────────────────────
    df_rows = []
    for r in records:
        row = {col: r.get(col, "") for col in CES_COLUMNS if col != "extra_fields"}
        row["extra_fields"] = json.dumps(r.get("extra_fields", {}))
        df_rows.append(row)

    df_out = pd.DataFrame(df_rows, columns=CES_COLUMNS)

    out_path  = NORM_DIR / "loghub_hdfs_ces.csv"
    samp_path = SAMP_DIR / "loghub_hdfs_sample_500.csv"

    df_out.to_csv(out_path, index=False)
    df_out.sample(n=min(500, len(df_out)), random_state=42).to_csv(samp_path, index=False)

    print(f"\n  ✓ Normalized → {out_path.relative_to(ROOT)} ({out_path.stat().st_size/1024:.1f} KB)")
    print(f"  ✓ Sample     → {samp_path.relative_to(ROOT)}")

    # Anomaly type distribution
    anomaly_types = {}
    for r in records:
        if r["is_attack"]:
            k = r["attack_type"] or "Unknown"
            anomaly_types[k] = anomaly_types.get(k, 0) + 1
    if anomaly_types:
        print("\n  Anomaly type distribution:")
        for k, v in sorted(anomaly_types.items(), key=lambda x: -x[1]):
            print(f"    {k:35s}: {v}")


if __name__ == "__main__":
    main()
