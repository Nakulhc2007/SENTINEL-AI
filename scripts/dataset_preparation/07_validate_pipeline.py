"""
SENTINEL-AI — Dataset Validator & Summary Report
==================================================
Reads all CES CSVs from data/processed/normalized/
Validates schema compliance, checks integrity (SHA-256),
and prints a comprehensive dataset report.

Run: python scripts/dataset_preparation/07_validate_pipeline.py

Output: data/DATASET_SUMMARY.json  (machine-readable report)
        Console: human-readable table
"""

import sys
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT     = Path(__file__).resolve().parents[2]
NORM_DIR = ROOT / "data" / "processed" / "normalized"
SAMP_DIR = ROOT / "data" / "processed" / "samples"

sys.path.insert(0, str(ROOT / "scripts" / "dataset_preparation"))
from schema import validate_record, CES_COLUMNS, DOMAINS


def sha256_str(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8", errors="replace")).hexdigest()


def validate_ces_file(csv_path: Path) -> dict:
    """Validate one CES CSV file. Returns stats dict."""
    import pandas as pd

    df = pd.read_csv(csv_path, low_memory=False)

    stats = {
        "file":           csv_path.name,
        "path":           str(csv_path.relative_to(ROOT)),
        "size_kb":        round(csv_path.stat().st_size / 1024, 1),
        "total_records":  len(df),
        "real_records":   0,
        "synthetic_records": 0,
        "attack_records": 0,
        "benign_records": 0,
        "schema_errors":  0,
        "integrity_ok":   0,
        "integrity_fail": 0,
        "domains":        {},
        "severity_dist":  {"info":0,"low":0,"medium":0,"high":0,"critical":0},
        "attack_types":   {},
        "missing_cols":   [],
        "validation_errors": [],
    }

    # Check required columns
    missing = [c for c in CES_COLUMNS if c not in df.columns]
    if missing:
        stats["missing_cols"] = missing
        return stats

    for _, row in df.iterrows():
        # Build record-like dict
        r = {col: row.get(col, None) for col in CES_COLUMNS}
        r["extra_fields"] = {}   # Skip parsing JSON for speed

        # Schema validation
        errors = validate_record(r)
        if errors:
            stats["schema_errors"] += 1
            for e in errors[:2]:
                if e not in stats["validation_errors"]:
                    stats["validation_errors"].append(e)

        # Record type counts
        rtype = str(row.get("record_type", "")).strip()
        if rtype == "real":
            stats["real_records"] += 1
        elif rtype == "synthetic":
            stats["synthetic_records"] += 1

        # Attack / benign
        is_atk = str(row.get("is_attack", "")).strip().lower()
        if is_atk == "true":
            stats["attack_records"] += 1
            atype = str(row.get("attack_type", "Unknown")).strip()
            stats["attack_types"][atype] = stats["attack_types"].get(atype, 0) + 1
        else:
            stats["benign_records"] += 1

        # Domain count
        d = str(row.get("domain", "unknown")).strip()
        stats["domains"][d] = stats["domains"].get(d, 0) + 1

        # Severity
        sev_label = str(row.get("severity_label", "info")).strip()
        if sev_label in stats["severity_dist"]:
            stats["severity_dist"][sev_label] += 1

        # SHA-256 integrity check (spot-check 5% of rows)
        import random
        if random.random() < 0.05:
            raw = str(row.get("raw_log", ""))
            stored_hash = str(row.get("sha256", "")).strip()
            computed    = sha256_str(raw)
            if stored_hash == computed:
                stats["integrity_ok"] += 1
            else:
                stats["integrity_fail"] += 1

    return stats


def main():
    import pandas as pd

    print("\n" + "=" * 70)
    print("  SENTINEL-AI — Dataset Validation Report")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    csv_files = sorted(NORM_DIR.glob("*_ces.csv"))
    if not csv_files:
        print(f"\n[ERROR] No CES CSV files found in {NORM_DIR}")
        print("  Run the pipeline first: python scripts/dataset_preparation/run_all.py")
        return

    all_stats  = []
    grand_real = grand_synth = grand_attacks = grand_total = grand_errors = 0

    for csv_path in csv_files:
        print(f"\n  Validating: {csv_path.name}")
        stats = validate_ces_file(csv_path)
        all_stats.append(stats)

        grand_total   += stats["total_records"]
        grand_real    += stats["real_records"]
        grand_synth   += stats["synthetic_records"]
        grand_attacks += stats["attack_records"]
        grand_errors  += stats["schema_errors"]

        pct_atk = (stats["attack_records"] / max(stats["total_records"], 1)) * 100
        pct_err = (stats["schema_errors"]  / max(stats["total_records"], 1)) * 100

        print(f"    Records   : {stats['total_records']:>8,}  "
              f"(real={stats['real_records']:,}, synthetic={stats['synthetic_records']:,})")
        print(f"    Attacks   : {stats['attack_records']:>8,}  ({pct_atk:.1f}%)")
        print(f"    Size      : {stats['size_kb']:>6.1f} KB")
        print(f"    Schema OK : {stats['total_records'] - stats['schema_errors']:>8,}  "
              f"errors={stats['schema_errors']} ({pct_err:.2f}%)")
        if stats["integrity_fail"]:
            print(f"    [WARN] SHA-256 integrity failures: {stats['integrity_fail']}")
        if stats["missing_cols"]:
            print(f"    [WARN] Missing columns: {stats['missing_cols']}")
        if stats["validation_errors"]:
            for e in stats["validation_errors"][:3]:
                print(f"    [ERR]  {e}")

    # ── Grand summary table ────────────────────────────────────────────────────
    print("\n\n" + "=" * 70)
    print("  CONSOLIDATED SUMMARY")
    print("=" * 70)
    print(f"  {'Metric':<35} {'Value':>15}")
    print("  " + "-" * 52)
    print(f"  {'Total CES files processed':<35} {len(csv_files):>15,}")
    print(f"  {'Total records (all files)':<35} {grand_total:>15,}")
    print(f"  {'Real dataset records':<35} {grand_real:>15,}")
    print(f"  {'Synthetic records':<35} {grand_synth:>15,}")
    print(f"  {'Attack / malicious records':<35} {grand_attacks:>15,}")
    print(f"  {'Benign / normal records':<35} {grand_total - grand_attacks:>15,}")
    print(f"  {'Schema validation errors':<35} {grand_errors:>15,}")

    attack_pct = grand_attacks / max(grand_total, 1) * 100
    real_pct   = grand_real    / max(grand_total, 1) * 100
    print(f"\n  {'Attack ratio':<35} {attack_pct:>14.1f}%")
    print(f"  {'Real data ratio':<35} {real_pct:>14.1f}%")

    # Domain coverage
    all_domains = {}
    for s in all_stats:
        for d, c in s["domains"].items():
            all_domains[d] = all_domains.get(d, 0) + c
    print(f"\n  Domain Coverage ({len(all_domains)}/8 of 8 domains):")
    for d in DOMAINS:
        n = all_domains.get(d, 0)
        status = "✓" if n > 0 else "✗ MISSING"
        print(f"    {status}  {d:<28} : {n:>7,} records")

    # ── Write machine-readable summary ──────────────────────────────────────
    summary = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "total_files":      len(csv_files),
        "grand_total":      grand_total,
        "grand_real":       grand_real,
        "grand_synthetic":  grand_synth,
        "grand_attacks":    grand_attacks,
        "grand_benign":     grand_total - grand_attacks,
        "attack_pct":       round(attack_pct, 2),
        "schema_errors":    grand_errors,
        "domain_coverage":  all_domains,
        "files":            all_stats,
    }

    out_path = ROOT / "data" / "DATASET_SUMMARY.json"
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\n  ✓ Report saved → data/DATASET_SUMMARY.json")

    # Final verdict
    all_domains_covered = all(all_domains.get(d, 0) > 0 for d in DOMAINS)
    if grand_errors == 0 and all_domains_covered:
        print("\n  ✅  VALIDATION PASSED — All 8 domains covered, no schema errors.")
    elif grand_errors == 0:
        print("\n  ⚠️   Some domains are missing data — run synthetic generator.")
    else:
        print(f"\n  ⚠️   {grand_errors} schema errors detected. Check validation_errors in DATASET_SUMMARY.json")

    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
