"""
run_aria.py — ARIA CLI Entry Point
Run the full ARIA pipeline from the command line.

Usage:
    # Demo mode (uses built-in Acme HealthTech description):
    python3 run_aria.py

    # Custom org description from a text file:
    python3 run_aria.py --org-file my_org.txt --org-name "My Company"

    # Analyze specific CVEs only:
    python3 run_aria.py --cve CVE-2024-1234 CVE-2024-5678

    # Filter by year and severity:
    python3 run_aria.py --min-year 2024 --severities CRITICAL HIGH

    # Custom output directory:
    python3 run_aria.py --output output/my_run
"""

import argparse
import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.orchestrator import run_pipeline
from agents.agent_04_business import DEMO_ORG


def main():
    parser = argparse.ArgumentParser(
        description="ARIA — Autonomous Risk Intelligence Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--org-file", "-f",
        help="Path to a plain-text file describing your organization. "
             "If not provided, uses the built-in demo org (Acme HealthTech)."
    )
    parser.add_argument(
        "--org-name", "-n",
        default="Acme HealthTech (Demo)",
        help="Display name for the organization in the report."
    )
    parser.add_argument(
        "--cve", nargs="+",
        help="Specific CVE IDs to analyze (e.g. CVE-2024-1234). "
             "If not provided, analyzes all CVEs in the NVD sample."
    )
    parser.add_argument(
        "--min-year", type=int, default=None,
        help="Only include CVEs published on or after this year (e.g. 2024)."
    )
    parser.add_argument(
        "--severities", nargs="+",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Only include CVEs of these severity levels."
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for report files. Default: output/"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output (errors still shown)."
    )

    args = parser.parse_args()

    # ── Load org description ──────────────────────────────────────────────────
    if args.org_file:
        if not os.path.exists(args.org_file):
            print(f"Error: org file not found: {args.org_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.org_file) as f:
            org_description = f.read()
        if not args.org_name or args.org_name == "Acme HealthTech (Demo)":
            args.org_name = os.path.splitext(os.path.basename(args.org_file))[0]
    else:
        org_description = DEMO_ORG
        if not args.quiet:
            print("\n[ARIA] No --org-file provided. Running demo with Acme HealthTech.\n")

    # ── Run pipeline ──────────────────────────────────────────────────────────
    try:
        report = run_pipeline(
            org_description = org_description,
            org_name        = args.org_name,
            cve_ids         = args.cve,
            min_year        = args.min_year,
            severities      = args.severities,
            output_dir      = args.output,
            verbose         = not args.quiet,
        )
    except Exception as e:
        print(f"\n[ARIA] Pipeline error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # ── Print summary to stdout ───────────────────────────────────────────────
    if not args.quiet:
        es = report.get("executive_summary", {})
        print("\n" + "━"*60)
        print("ARIA REPORT SUMMARY")
        print("━"*60)
        print(es.get("headline", ""))
        print()
        for bullet in es.get("bullets", []):
            print(f"  • {bullet}")
        print()
        print(f"  {es.get('immediate_action', '')}")
        print()
        print("Output files:")
        for f in report.get("files_written", []):
            print(f"  {f}")
        print("━"*60 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
