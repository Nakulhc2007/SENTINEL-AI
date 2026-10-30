"""
SENTINEL-AI — Dataset Pipeline Orchestrator
=============================================
Runs all dataset preparation steps in sequence.

Usage:
  python scripts/dataset_preparation/run_all.py            # full pipeline
  python scripts/dataset_preparation/run_all.py --skip-download # skip downloads
  python scripts/dataset_preparation/run_all.py --only-synthetic # only synthetic

Steps:
  1. Download real datasets (CIC-IDS2017, LogHub)
  2. Preprocess CIC-IDS2017
  3. Preprocess LogHub HDFS
  4. Preprocess CERT Insider Threat (real or synthetic fallback)
  5. Generate synthetic logs (all 8 domains)
  6. Merge and validate all CES files

Output: data/ directory fully populated and validated
"""

import sys
import time
import argparse
import subprocess
from pathlib import Path

ROOT         = Path(__file__).resolve().parents[2]
SCRIPTS_DIR  = Path(__file__).parent


def run_step(script_name: str, description: str) -> bool:
    """Run a pipeline step. Returns True on success."""
    script_path = SCRIPTS_DIR / script_name
    print(f"\n{'─'*70}")
    print(f"  STEP: {description}")
    print(f"  Script: {script_name}")
    print(f"{'─'*70}")

    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(ROOT),
            capture_output=False,
        )
        elapsed = time.time() - start
        if result.returncode == 0:
            print(f"\n  ✓ Completed in {elapsed:.1f}s")
            return True
        else:
            print(f"\n  ✗ FAILED (exit code {result.returncode}) after {elapsed:.1f}s")
            return False
    except FileNotFoundError:
        print(f"\n  ✗ Script not found: {script_path}")
        return False
    except Exception as e:
        print(f"\n  ✗ Error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL-AI Dataset Pipeline Orchestrator")
    parser.add_argument("--skip-download", action="store_true",
                        help="Skip dataset downloads (step 1)")
    parser.add_argument("--only-synthetic", action="store_true",
                        help="Run only synthetic generator + validator")
    parser.add_argument("--skip-validate", action="store_true",
                        help="Skip final validation step")
    args = parser.parse_args()

    print("\n" + "═" * 70)
    print("  SENTINEL-AI — Full Dataset Preparation Pipeline")
    print(f"  Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 70)

    steps_run  = 0
    steps_ok   = 0
    steps_fail = 0

    if args.only_synthetic:
        # Minimal: just generate synthetic data + validate
        steps = [
            ("06_synthetic_generator.py", "Generate Synthetic Logs (All 8 Domains)"),
            ("07_validate_pipeline.py",   "Validate All CES Files"),
        ]
    else:
        steps = []
        if not args.skip_download:
            steps.append(("02_download_datasets.py",   "Download Real Datasets"))
        steps += [
            ("03_preprocess_cicids2017.py", "Preprocess CIC-IDS2017 (Network Security)"),
            ("04_preprocess_loghub.py",     "Preprocess LogHub HDFS (Endpoint Security)"),
            ("05_preprocess_cert.py",       "Preprocess CERT Insider Threat"),
            ("06_synthetic_generator.py",   "Generate Synthetic Logs (All 8 Domains)"),
        ]
        if not args.skip_validate:
            steps.append(("07_validate_pipeline.py", "Validate All CES Files"))

    for script_name, description in steps:
        steps_run += 1
        ok = run_step(script_name, description)
        if ok:
            steps_ok += 1
        else:
            steps_fail += 1
            response = input(f"\n  Step failed. Continue anyway? [y/N]: ").strip().lower()
            if response != "y":
                print("  Pipeline aborted by user.")
                break

    # Final summary
    print("\n" + "═" * 70)
    print("  PIPELINE COMPLETE")
    print(f"  Steps run: {steps_run}  ✓ OK: {steps_ok}  ✗ Failed: {steps_fail}")
    print(f"  Finished:  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 70)

    if steps_fail == 0:
        print("\n  ✅  All steps passed. Check data/ for results.")
        print(f"  📁  data/raw/          — original raw data files")
        print(f"  📁  data/processed/normalized/ — CES normalized CSVs")
        print(f"  📁  data/processed/samples/    — 200-1000 row samples")
        print(f"  📄  data/DATASET_SUMMARY.json  — full report\n")
    else:
        print(f"\n  ⚠️   {steps_fail} step(s) failed. Check output above.\n")

    sys.exit(0 if steps_fail == 0 else 1)


if __name__ == "__main__":
    main()
