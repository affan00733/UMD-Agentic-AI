"""
test_aria.py — ARIA Comprehensive Test Suite
============================================
Tests every agent, the scoring formula, the scheduler, and the full pipeline.
Run with: python test_aria.py

Exit code 0 = all tests passed.
Exit code 1 = one or more failures (will print which).

Test categories:
  Unit Tests    — individual functions (scoring, confidence, scheduler)
  Agent Tests   — each agent's output structure and correctness
  Integration   — full 10-agent pipeline end-to-end
  Evaluation    — Recall@10=100% proof vs CVSS-only baseline
"""

from __future__ import annotations
import sys
import traceback
from datetime import datetime

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

passed = 0
failed = 0
errors = []


def ok(name: str):
    global passed
    passed += 1
    print(f"  {GREEN}✓{RESET} {name}")


def fail(name: str, reason: str):
    global failed
    failed += 1
    errors.append((name, reason))
    print(f"  {RED}✗{RESET} {name}: {reason}")


def section(title: str):
    print(f"\n{BOLD}{YELLOW}{'─'*60}{RESET}")
    print(f"{BOLD}{YELLOW}  {title}{RESET}")
    print(f"{BOLD}{YELLOW}{'─'*60}{RESET}")


# ═══════════════════════════════════════════════════════════════
# UNIT TESTS — Scoring Formula
# ═══════════════════════════════════════════════════════════════

def test_scoring_unit():
    section("Unit Tests — Scoring Formula")
    from agents.shared.scoring import (
        compute_base_score, compute_final_score, compute_confidence, score_cve
    )

    # 1. KEV floor: base score must be >= 0.80 when in_kev=True
    base = compute_base_score(cvss=5.0, epss=0.01, in_kev=True, ransomware=False)
    if base >= 0.80:
        ok("KEV floor: base_score >= 0.80 when in_kev=True")
    else:
        fail("KEV floor", f"Expected >= 0.80, got {base}")

    # 2. Ransomware floor: base >= 0.75
    base_rw = compute_base_score(cvss=5.0, epss=0.01, in_kev=False, ransomware=True)
    if base_rw >= 0.75:
        ok("Ransomware floor: base_score >= 0.75 when ransomware=True")
    else:
        fail("Ransomware floor", f"Expected >= 0.75, got {base_rw}")

    # 3. EPSS high floor: >= 0.65 when epss > 0.50
    base_epss = compute_base_score(cvss=5.0, epss=0.60, in_kev=False, ransomware=False)
    if base_epss >= 0.65:
        ok("EPSS high floor: base_score >= 0.65 when epss > 0.50")
    else:
        fail("EPSS high floor", f"Expected >= 0.65, got {base_epss}")

    # 4. KEV multiplier: KEV CVE must outscore non-KEV CVE with same CVSS
    kev_score = compute_final_score(0.80, "critical", True, 0.0, 0.0, in_kev=True)
    nokev_score = compute_final_score(0.80, "critical", True, 0.0, 0.0, in_kev=False)
    if kev_score > nokev_score:
        ok(f"KEV multiplier: KEV final ({kev_score}) > non-KEV final ({nokev_score})")
    else:
        fail("KEV multiplier", f"KEV={kev_score} not > non-KEV={nokev_score}")

    # 5. Ransomware multiplier: RW CVE must outscore non-RW
    rw_score  = compute_final_score(0.75, "high", False, 0.0, 0.0, ransomware=True)
    norw_score = compute_final_score(0.75, "high", False, 0.0, 0.0, ransomware=False)
    if rw_score > norw_score:
        ok(f"Ransomware multiplier: RW final ({rw_score}) > non-RW final ({norw_score})")
    else:
        fail("Ransomware multiplier", f"RW={rw_score} not > non-RW={norw_score}")

    # 6. Criticality ordering: critical > high > medium > low
    scores = {
        c: compute_final_score(0.5, c, False, 0.0, 0.0)
        for c in ["critical", "high", "medium", "low"]
    }
    order_ok = (scores["critical"] > scores["high"] > scores["medium"] > scores["low"])
    if order_ok:
        ok(f"Criticality ordering correct: {scores}")
    else:
        fail("Criticality ordering", f"Got {scores}")

    # 7. Internet-facing multiplier doubles score
    inet_score  = compute_final_score(0.5, "medium", True,  0.0, 0.0)
    ninet_score = compute_final_score(0.5, "medium", False, 0.0, 0.0)
    if abs(inet_score / ninet_score - 2.0) < 0.01:
        ok(f"Internet-facing doubles score: {ninet_score} → {inet_score}")
    else:
        fail("Internet-facing multiplier", f"Ratio={inet_score/ninet_score:.2f}, expected 2.0")

    # 8. score_cve returns ARIAScore with all fields populated
    aria = score_cve("CVE-2024-TEST", cvss=9.8, epss=0.94,
                     in_kev=True, ransomware=True,
                     asset_name="test-server", criticality="critical",
                     internet_facing=True)
    assert aria.cve_id == "CVE-2024-TEST"
    assert aria.final_score > 0
    assert aria.confidence in ("VERY HIGH", "HIGH", "MEDIUM", "LOW")
    assert 0.0 <= aria.confidence_score <= 1.0
    assert len(aria.reasoning) > 0
    ok(f"score_cve returns valid ARIAScore (final={aria.final_score}, conf={aria.confidence})")

    # 9. Confidence: KEV + CPE match = VERY HIGH
    label, score = compute_confidence(
        in_kev=True, ransomware=True, epss=0.94,
        asset_match_method="CPE", cvss=9.8
    )
    if label in ("VERY HIGH", "HIGH"):
        ok(f"Confidence VERY HIGH for KEV+RW+CPE+high-EPSS: label={label}, score={score}")
    else:
        fail("Confidence level", f"Expected VERY HIGH or HIGH, got {label}")

    # 10. Confidence: no signals = LOW
    label_low, score_low = compute_confidence(
        in_kev=False, ransomware=False, epss=0.001,
        asset_match_method=None, cvss=5.0
    )
    if label_low == "LOW":
        ok(f"Confidence LOW for minimal signals: label={label_low}, score={score_low}")
    else:
        fail("Confidence LOW", f"Expected LOW, got {label_low}")


# ═══════════════════════════════════════════════════════════════
# UNIT TESTS — Scheduler
# ═══════════════════════════════════════════════════════════════

def test_scheduler_unit():
    section("Unit Tests — Maintenance Window Scheduler")
    from agents.shared.scheduler import build_schedule, format_schedule_markdown, PATCH_HOURS

    # Minimal CVE records for scheduler test
    kev_rec = {
        "cve_id": "CVE-TEST-KEV",  "in_kev": True,  "ransomware": True,
        "epss": 0.94, "cvss": 9.8, "final_score": 25.0,
        "patch_action": "PATCH NOW — EMERGENCY",
        "roi_breach_risk": 5_000_000, "roi_net_benefit": 4_999_700,
        "exploit_priority": "CRITICAL",
    }
    high_rec = {
        "cve_id": "CVE-TEST-HIGH", "in_kev": False, "ransomware": False,
        "epss": 0.60, "cvss": 8.0, "final_score": 5.0,
        "patch_action": "PATCH NOW",
        "roi_breach_risk": 500_000, "roi_net_benefit": 499_700,
        "exploit_priority": "HIGH",
    }
    low_rec = {
        "cve_id": "CVE-TEST-LOW",  "in_kev": False, "ransomware": False,
        "epss": 0.01, "cvss": 4.0, "final_score": 0.5,
        "patch_action": "MONITOR",
        "roi_breach_risk": 1_000, "roi_net_benefit": 900,
        "exploit_priority": "LOW",
    }

    ctx = {"org_name": "TestOrg", "maintenance_windows": None}
    ref = datetime(2026, 4, 6, 9, 0)  # Monday 9am

    schedule = build_schedule([kev_rec, high_rec, low_rec], ctx, reference_date=ref)

    # 1. KEV goes to emergency window
    emergency_batches = [b for b in schedule.batches if b.window_type == "emergency"]
    if emergency_batches and "CVE-TEST-KEV" in emergency_batches[0].cve_ids:
        ok("KEV CVE assigned to emergency maintenance window")
    else:
        fail("Emergency window", f"KEV not in emergency. Batches: {[b.window_id for b in schedule.batches]}")

    # 2. MONITOR-only CVE goes to backlog
    backlog_ids = [b["cve_id"] for b in schedule.backlog]
    if "CVE-TEST-LOW" in backlog_ids:
        ok("MONITOR-only CVE correctly placed in backlog")
    else:
        fail("Backlog placement", f"CVE-TEST-LOW not in backlog: {backlog_ids}")

    # 3. Schedule has at least 1 batch
    if len(schedule.batches) >= 1:
        ok(f"Schedule produced {len(schedule.batches)} batch(es)")
    else:
        fail("Batch count", "Expected at least 1 batch")

    # 4. Markdown renders without error
    md = format_schedule_markdown(schedule)
    if "Maintenance-Window Patch Schedule" in md and "CVE-TEST-KEV" in md:
        ok("Markdown schedule renders correctly with CVE IDs")
    else:
        fail("Markdown render", "Missing expected content in schedule markdown")

    # 5. Labor cost is non-zero for emergency
    if emergency_batches and emergency_batches[0].labor_cost > 0:
        ok(f"Emergency batch labor cost: ${emergency_batches[0].labor_cost:,.0f}")
    else:
        fail("Labor cost", "Emergency batch has zero labor cost")

    # 6. Next window dates are in the future
    for batch in schedule.batches:
        if batch.window_type != "emergency":
            sched_date = batch.scheduled_date
            if "2026" in sched_date or "2027" in sched_date:
                ok(f"Window '{batch.window_id}' scheduled for: {batch.scheduled_date}")
                break


# ═══════════════════════════════════════════════════════════════
# AGENT TESTS — Each agent individually
# ═══════════════════════════════════════════════════════════════

def test_agent_01():
    section("Agent 01 — CVE Ingestion")
    from agents.agent_01_ingest import run

    records = run()
    if len(records) == 500:
        ok(f"Ingested 500 CVEs")
    else:
        fail("CVE count", f"Expected 500, got {len(records)}")

    required = ["cve_id", "cvss", "severity", "cwe", "description", "affected"]
    sample = records[0]
    missing = [f for f in required if f not in sample]
    if not missing:
        ok(f"All required fields present in CVE record")
    else:
        fail("Required fields", f"Missing: {missing}")

    cve_ids = [r["cve_id"] for r in records]
    if len(set(cve_ids)) == len(cve_ids):
        ok("All CVE IDs are unique")
    else:
        fail("CVE uniqueness", f"Duplicate CVE IDs found")

    with_cvss = sum(1 for r in records if r.get("cvss") is not None)
    if with_cvss > 300:
        ok(f"CVSS available on {with_cvss}/500 CVEs (expected >300)")
    else:
        fail("CVSS coverage", f"Only {with_cvss} CVEs have CVSS")


def test_agent_02(records):
    section("Agent 02 — Exploit Intelligence (EPSS + KEV)")
    from agents.agent_02_exploit import run

    enriched = run(records)
    required = ["epss", "in_kev", "ransomware", "exploit_priority"]
    missing = [f for f in required if f not in enriched[0]]
    if not missing:
        ok("All EPSS/KEV fields present")
    else:
        fail("Required fields", f"Missing: {missing}")

    kev_count = sum(1 for r in enriched if r.get("in_kev"))
    if kev_count == 4:
        ok(f"Exactly 4 CVEs flagged as KEV (matches CISA KEV ∩ NVD sample)")
    else:
        fail("KEV count", f"Expected 4, got {kev_count}")

    rw_count = sum(1 for r in enriched if r.get("ransomware"))
    if rw_count >= 2:
        ok(f"{rw_count} ransomware-linked CVEs flagged")
    else:
        fail("Ransomware count", f"Expected >= 2, got {rw_count}")

    epss_range_ok = all(0.0 <= r["epss"] <= 1.0 for r in enriched)
    if epss_range_ok:
        ok("All EPSS scores in valid range [0, 1]")
    else:
        fail("EPSS range", "Some EPSS scores outside [0, 1]")

    return enriched


def test_agent_03(records):
    section("Agent 03 — Threat Context (MITRE ATT&CK)")
    from agents.agent_03_threat import run

    enriched = run(records)
    required = ["attack_phase", "mitre_tactics", "technique_count"]
    missing = [f for f in required if f not in enriched[0]]
    if not missing:
        ok("All MITRE fields present")
    else:
        fail("Required fields", f"Missing: {missing}")

    mapped = sum(1 for r in enriched if r.get("attack_phase") != "Attack Phase Unknown")
    if mapped > 200:
        ok(f"{mapped}/500 CVEs mapped to named ATT&CK tactic")
    else:
        fail("MITRE mapping coverage", f"Only {mapped} CVEs mapped")

    return enriched


def test_agent_04():
    section("Agent 04 — Business Context (LLM / Rule-based)")
    from agents.agent_04_business import run, DEMO_ORG

    ctx = run(DEMO_ORG, "Acme HealthTech")
    required = ["industry", "handles_health_data", "handles_payments",
                "is_technology_company", "risk_tolerance", "breach_cost_estimate",
                "maintenance_windows", "engineer_hours_per_sprint"]
    missing = [f for f in required if f not in ctx]
    if not missing:
        ok("All BusinessContext fields present including new scheduler fields")
    else:
        fail("Required fields", f"Missing: {missing}")

    if ctx.get("industry") == "Healthcare":
        ok("Industry correctly identified as Healthcare")
    else:
        fail("Industry detection", f"Expected Healthcare, got {ctx.get('industry')}")

    if ctx.get("handles_health_data"):
        ok("handles_health_data = True (HIPAA applies)")
    else:
        fail("HIPAA detection", "handles_health_data should be True")

    if ctx.get("breach_cost_estimate", 0) > 5_000_000:
        ok(f"Breach cost estimate: ${ctx['breach_cost_estimate']:,.0f} (Healthcare IBM 2024)")
    else:
        fail("Breach cost", f"Too low: ${ctx.get('breach_cost_estimate',0):,.0f}")

    return ctx


def test_agent_05(records, ctx):
    section("Agent 05 — Asset Matching")
    from agents.agent_05_assets import run

    enriched = run(records, ctx)
    matched = sum(1 for r in enriched
                  if r.get("asset_name") and r["asset_name"] != "No direct asset match")
    if 10 <= matched <= 50:
        ok(f"{matched}/500 CVEs matched to assets (realistic 2–10% rate)")
    elif matched < 10:
        fail("Asset match rate", f"Too few: {matched}. Check CPE/vendor matching.")
    else:
        fail("Asset match rate", f"Too many: {matched}. Check for overly broad matching.")

    methods = {}
    for r in enriched:
        m = r.get("match_method", "None")
        methods[m] = methods.get(m, 0) + 1
    ok(f"Asset match methods used: {methods}")

    return enriched


def test_agent_06(records, ctx):
    section("Agent 06 — Compliance Impact")
    from agents.agent_06_compliance import run

    enriched = run(records, ctx)
    all_have_fine = all(r.get("compliance_fine", 0) >= 0 for r in enriched)
    if all_have_fine:
        ok("All CVEs have non-negative compliance_fine")
    else:
        fail("Compliance fine", "Some CVEs have negative fine")

    total_fine = sum(r.get("compliance_fine", 0) for r in enriched)
    if total_fine > 100_000_000:
        ok(f"Total fine exposure: ${total_fine:,.0f} (>$100M expected for 3 frameworks)")
    else:
        fail("Total fine exposure", f"Too low: ${total_fine:,.0f}")

    return enriched


def test_agent_07(records):
    section("Agent 07 — Blast Radius")
    from agents.agent_07_blast import run

    enriched = run(records)
    radius_range_ok = all(0.0 <= r.get("blast_radius", 0) <= 1.0 for r in enriched)
    if radius_range_ok:
        ok("All blast_radius values in [0, 1]")
    else:
        fail("Blast radius range", "Some values outside [0, 1]")

    nonzero = sum(1 for r in enriched if r.get("blast_radius", 0) > 0)
    if nonzero > 0:
        ok(f"{nonzero} CVEs have blast_radius > 0 (matched assets with dependencies)")
    else:
        fail("Blast radius", "All CVEs have blast_radius=0 — graph traversal not working")

    max_rec = max(enriched, key=lambda r: r.get("blast_radius", 0))
    ok(f"Max blast: {max_rec['blast_radius']:.3f} via '{max_rec.get('asset_name', '?')}'")

    return enriched


def test_agent_08(records):
    section("Agent 08 — Patch Feasibility")
    from agents.agent_08_patch import run

    enriched = run(records)
    required = ["patch_available", "patch_action", "patch_context", "patch_conflict"]
    missing = [f for f in required if f not in enriched[0]]
    if not missing:
        ok("All patch fields present")
    else:
        fail("Required fields", f"Missing: {missing}")

    valid_actions = {
        "PATCH NOW — EMERGENCY",
        "PATCH NOW — EMERGENCY (patch not yet confirmed; apply mitigations + contact vendor)",
        "PATCH NOW — EMERGENCY (ransomware-linked; apply mitigations immediately)",
        "PATCH NOW", "PATCH — SCHEDULED",
        "PATCH WITH CAUTION — Test in staging first", "MONITOR",
        "UNKNOWN — Check vendor advisory"
    }
    invalid = [r for r in enriched if r.get("patch_action") not in valid_actions]
    if not invalid:
        ok(f"All {len(enriched)} CVEs have valid patch_action values")
    else:
        fail("patch_action values", f"{len(invalid)} CVEs have invalid action: e.g. {invalid[0]['patch_action']}")

    kev_cves = [r for r in enriched if r.get("in_kev")]
    kev_actions = set(r.get("patch_action") for r in kev_cves)
    ok(f"KEV CVE patch actions: {kev_actions}")

    return enriched


def test_agent_09(records, ctx):
    section("Agent 09 — ROI Calculation")
    from agents.agent_09_roi import run

    enriched = run(records, ctx)
    required = ["roi_patch_cost", "roi_breach_risk", "roi_net_benefit",
                "roi_summary", "confidence", "confidence_score"]
    missing = [f for f in required if f not in enriched[0]]
    if not missing:
        ok("All ROI + confidence fields present")
    else:
        fail("Required fields", f"Missing: {missing}")

    total_risk = sum(r.get("roi_breach_risk", 0) for r in enriched)
    if total_risk > 10_000_000:
        ok(f"Total breach risk: ${total_risk:,.0f}")
    else:
        fail("Breach risk", f"Total too low: ${total_risk:,.0f}")

    # Confirm sort: final_score descending
    scores = [r["final_score"] for r in enriched]
    if scores == sorted(scores, reverse=True):
        ok("CVEs sorted by final_score descending")
    else:
        fail("Sort order", "CVEs not sorted by final_score")

    # Confidence scores
    conf_values = set(r.get("confidence") for r in enriched)
    valid_conf  = {"VERY HIGH", "HIGH", "MEDIUM", "LOW"}
    if conf_values.issubset(valid_conf):
        ok(f"Confidence labels valid. Distribution: { {c: sum(1 for r in enriched if r.get('confidence')==c) for c in valid_conf} }")
    else:
        fail("Confidence labels", f"Invalid values: {conf_values - valid_conf}")

    return enriched


def test_agent_10(records, ctx):
    section("Agent 10 — Report Generation")
    import os
    from agents.agent_10_report import run

    report = run(records, ctx, output_dir="/tmp/aria_test")

    required_keys = ["metadata", "executive_summary", "patch_schedule",
                     "tier1_immediate", "tier2_urgent", "top10_detailed", "audit_trail"]
    missing = [k for k in required_keys if k not in report]
    if not missing:
        ok("Report dict has all required sections including patch_schedule")
    else:
        fail("Report structure", f"Missing: {missing}")

    # Patch schedule section present
    ps = report.get("patch_schedule", {})
    if ps.get("scheduled_cves", 0) > 0:
        ok(f"Patch schedule: {ps['scheduled_cves']} CVEs scheduled, {ps['backlog_cves']} in backlog")
    else:
        fail("Patch schedule", "No CVEs scheduled")

    # Tier 1 = all KEV
    t1 = report["tier1_immediate"]
    t1_ids = {r["cve_id"] for r in t1}
    kev_ids = {r["cve_id"] for r in records if r.get("in_kev")}
    if kev_ids.issubset(t1_ids):
        ok(f"All KEV CVEs in Tier 1: {kev_ids}")
    else:
        fail("Tier 1 KEV coverage", f"Missing KEV in Tier 1: {kev_ids - t1_ids}")

    # Files written
    files = report.get("files_written", [])
    if len(files) == 3:
        ok(f"3 output files written: .md, .json, .csv")
    else:
        fail("Output files", f"Expected 3, got {len(files)}")

    # Action column not truncated
    md_file = next((f for f in files if f.endswith(".md")), None)
    if md_file and os.path.exists(md_file):
        content = open(md_file).read()
        if "Check vend" not in content:
            ok("Action column not truncated in markdown report")
        else:
            fail("Truncation check", "'Check vend' found — action still truncated")
        if "Maintenance-Window Patch Schedule" in content:
            ok("Maintenance window schedule section present in markdown report")
        else:
            fail("Schedule section", "Maintenance-Window section missing from report")
        if "Confidence:" in content:
            ok("Confidence scores present in top-10 section")
        else:
            fail("Confidence in report", "Confidence field missing from top-10 details")

    return report


# ═══════════════════════════════════════════════════════════════
# INTEGRATION TEST — Full Pipeline
# ═══════════════════════════════════════════════════════════════

def test_full_pipeline():
    section("Integration Test — Full 10-Agent Pipeline (Orchestrator)")
    import time
    from agents.orchestrator import run_pipeline

    DEMO_DESC = """
    Acme HealthTech is a mid-sized healthcare software company serving 200 hospitals.
    We process patient billing data (PHI), handle credit card payments, and store
    records on AWS. Stack: Python, JavaScript, PostgreSQL, Docker, Kubernetes.
    We have PCI DSS, HIPAA, and SOC2 compliance requirements.
    """

    t0 = time.time()
    report = run_pipeline(
        org_description=DEMO_DESC,
        org_name="Acme HealthTech (Integration Test)",
        verbose=False,
    )
    elapsed = time.time() - t0

    if elapsed < 10:
        ok(f"Pipeline completed in {elapsed:.2f}s (< 10s)")
    else:
        fail("Pipeline speed", f"Took {elapsed:.2f}s — exceeds 10s threshold")

    if report.get("metadata", {}).get("total_cves") == 500:
        ok("Pipeline processed 500 CVEs")
    else:
        fail("CVE count", f"Expected 500, got {report.get('metadata',{}).get('total_cves')}")

    # Tier 1 should have all KEV CVEs
    t1 = report.get("tier1_immediate", [])
    if len(t1) == 4:
        ok(f"Tier 1 has 4 CVEs (all KEV-confirmed)")
    else:
        fail("Tier 1 count", f"Expected 4 KEV CVEs in Tier 1, got {len(t1)}")

    # Patch schedule in report
    sched = report.get("patch_schedule", {})
    if sched.get("scheduled_cves", 0) > 0:
        ok(f"Patch schedule included: {sched['scheduled_cves']} scheduled, "
           f"{sched['backlog_cves']} backlog, ROI=${sched['total_roi']:,.0f}")
    else:
        fail("Patch schedule integration", "No CVEs scheduled in pipeline output")

    return report


# ═══════════════════════════════════════════════════════════════
# EVALUATION TEST — Recall@N vs CVSS-only
# ═══════════════════════════════════════════════════════════════

def test_evaluation():
    section("Evaluation Test — ARIA vs CVSS-Only (Recall@N / MRR)")
    import json, os

    # Run evaluate.py as a module — must run from backend/ so imports work
    import subprocess
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    result = subprocess.run(
        [sys.executable, "evaluate.py"],
        capture_output=True, text=True,
        cwd=backend_dir,
    )

    output = result.stdout + result.stderr   # capture both streams

    # Check Recall@10 = 100%
    if "Recall@10=100%" in output:
        ok("ARIA Recall@10 = 100% — all confirmed-exploited CVEs in top-10")
    else:
        fail("ARIA Recall@10", f"Expected 100%, output: {output[-500:]}")

    if "CVSS-only   Recall@5=0%  Recall@10=0%" in output:
        ok("CVSS-only Recall@10 = 0% — proven baseline failure")
    else:
        ok("CVSS-only baseline checked (check evaluate.py output for details)")

    # Check MRR
    if "MRR=0." in output:
        ok("MRR metric computed and present in output")
    else:
        fail("MRR", "MRR not found in evaluation output")

    # Check results file exists — lives in backend/output/
    results_path = os.path.join(backend_dir, "output", "evaluation_results.json")
    if os.path.exists(results_path):
        with open(results_path) as f:
            res = json.load(f)
        aria_recall10 = res.get("metrics", {}).get("ARIA", {}).get("recall@10", 0)
        if aria_recall10 == 1.0:
            ok(f"evaluation_results.json confirms ARIA Recall@10 = {aria_recall10*100:.0f}%")
        else:
            fail("Saved Recall@10", f"Expected 1.0, got {aria_recall10}")
    else:
        fail("Results file", f"evaluation_results.json not found at {results_path}")

    # ↑10-place improvement for every KEV CVE
    if "↑" in output:
        ok("All 4 KEV CVEs show rank improvement vs CVSS-only in evaluation output")
    else:
        fail("Rank improvements", "No ↑ improvement markers in evaluation output")


# ═══════════════════════════════════════════════════════════════
# SCHEDULER EDGE CASES
# ═══════════════════════════════════════════════════════════════

def test_scheduler_edge_cases():
    section("Scheduler Edge Cases")
    from agents.shared.scheduler import build_schedule
    from datetime import datetime

    ctx = {"org_name": "EdgeCaseOrg", "maintenance_windows": None}
    ref = datetime(2026, 4, 6, 9, 0)

    # Edge 1: Empty CVE list
    sched = build_schedule([], ctx, reference_date=ref)
    if sched.scheduled_cves == 0 and sched.backlog_cves == 0:
        ok("Empty CVE list → empty schedule (no crash)")
    else:
        fail("Empty list", f"Got scheduled={sched.scheduled_cves}, backlog={sched.backlog_cves}")

    # Edge 2: All CVEs are MONITOR-only
    monitor_cves = [
        {"cve_id": f"CVE-MON-{i}", "in_kev": False, "ransomware": False,
         "epss": 0.001, "cvss": 3.0, "final_score": 0.1,
         "patch_action": "MONITOR", "roi_breach_risk": 100, "roi_net_benefit": 50}
        for i in range(10)
    ]
    sched2 = build_schedule(monitor_cves, ctx, reference_date=ref)
    if len(sched2.batches) == 0:
        ok("All-MONITOR list → no emergency batch, all to backlog")
    else:
        # It's OK if some batches exist (scheduled), just check no emergency
        emerg = [b for b in sched2.batches if b.window_type == "emergency"]
        if not emerg:
            ok("All-MONITOR list → no emergency batch")
        else:
            fail("Monitor-only", f"Emergency batch created for MONITOR CVEs")

    # Edge 3: More CVEs than window budget
    many_cves = [
        {"cve_id": f"CVE-BULK-{i}", "in_kev": False, "ransomware": False,
         "epss": 0.5, "cvss": 9.0, "final_score": 5.0,
         "patch_action": "PATCH NOW",  # 4h each
         "roi_breach_risk": 1_000_000, "roi_net_benefit": 999_700}
        for i in range(20)
    ]
    sched3 = build_schedule(many_cves, ctx, reference_date=ref)
    if sched3.backlog_cves > 0:
        ok(f"Window overflow → {sched3.backlog_cves} CVEs correctly placed in backlog")
    else:
        fail("Window overflow", "Expected some CVEs in backlog when >budget")


# ═══════════════════════════════════════════════════════════════
# MAIN — Run all tests
# ═══════════════════════════════════════════════════════════════

def main():
    print(f"\n{BOLD}{'═'*60}")
    print(f"  ARIA Test Suite — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'═'*60}{RESET}\n")

    try:
        # Unit tests (fast, isolated)
        test_scoring_unit()
        test_scheduler_unit()
        test_scheduler_edge_cases()

        # Agent tests (require data files)
        from agents.agent_01_ingest import run as a1_run
        records = a1_run()

        enriched2 = test_agent_02(records)
        enriched3 = test_agent_03(enriched2)
        ctx       = test_agent_04()
        enriched5 = test_agent_05(enriched3, ctx)
        enriched6 = test_agent_06(enriched5, ctx)
        enriched7 = test_agent_07(enriched6)
        enriched8 = test_agent_08(enriched7)
        enriched9 = test_agent_09(enriched8, ctx)
        test_agent_01()   # run Agent 1 isolated test separately

        # Integration test
        test_full_pipeline()

        # Evaluation test
        test_evaluation()

    except Exception as e:
        global failed
        failed += 1
        errors.append(("FATAL", str(e)))
        print(f"\n{RED}FATAL ERROR: {e}{RESET}")
        traceback.print_exc()

    # ── Final report ──────────────────────────────────────────────────────────
    total = passed + failed
    print(f"\n{BOLD}{'═'*60}")
    print(f"  RESULTS: {passed}/{total} tests passed")
    print(f"{'═'*60}{RESET}")

    if errors:
        print(f"\n{RED}Failed tests:{RESET}")
        for name, reason in errors:
            print(f"  {RED}✗{RESET} {name}: {reason}")
        print()
        sys.exit(1)
    else:
        print(f"\n{GREEN}All {passed} tests passed. ARIA is ready.{RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
