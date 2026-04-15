"""
orchestrator.py — ARIA Orchestrator
Coordinates all 10 agents in the correct sequence, handles errors at each
stage gracefully, and returns the final ranked report.

LLM USAGE IN ORCHESTRATOR:
  The orchestrator uses Claude (claude-sonnet-4-5) for one specific step:
  "Final Triage Validation" — after all 10 agents have run, Claude reviews
  the top-5 ranked CVEs and checks:
    1. Does the ranking make intuitive sense given the combined signals?
    2. Are there any override recommendations (e.g. a KEV CVE ranked too low)?
    3. What is the single most important thing the security team should do today?

  WHY HERE: The orchestrator has visibility into ALL agent outputs simultaneously.
  Claude at this layer acts as a "senior analyst sanity check" on the machine-
  computed ranking — exactly how a real human analyst would review an automated
  system's output before sending it to the CISO.

  WHY NOT EARLIER: Individual agents deal with structured lookups and math where
  LLM involvement would introduce non-determinism into the scoring pipeline.
  The orchestrator is the only layer with sufficient context to do holistic reasoning.

Pipeline:
  Agent 1  → CVE Ingestion       (NVD)
  Agent 2  → Exploit Intelligence (EPSS + KEV)      [parallel w/ Agent 3]
  Agent 3  → Threat Context       (MITRE ATT&CK)    [parallel w/ Agent 2]
  Agent 4  → Business Context     (Claude or rules)  [runs once at startup]
  Agent 5  → Asset Matching       (CVE × inventory)
  Agent 6  → Compliance Impact    (PCI/HIPAA/SOC2)   [parallel w/ Agent 7]
  Agent 7  → Blast Radius         (dependency graph)  [parallel w/ Agent 6]
  Agent 8  → Patch Feasibility    (GitHub + MSRC)
  Agent 9  → ROI Calculation      (dollar value)
  Claude   → Final Triage Validation                  [sanity-check top-5]
  Agent 10 → Report Generation    (ranked output)

Usage:
    from agents.orchestrator import run_pipeline
    report = run_pipeline(org_description="...", org_name="Acme Corp")
"""

from __future__ import annotations
import os, time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import agents.agent_01_ingest    as a1
import agents.agent_02_exploit   as a2
import agents.agent_03_threat    as a3
import agents.agent_04_business  as a4
import agents.agent_05_assets    as a5
import agents.agent_06_compliance as a6
import agents.agent_07_blast     as a7
import agents.agent_08_patch     as a8
import agents.agent_09_roi       as a9
import agents.agent_10_report    as a10


def run_pipeline(
    org_description: str,
    org_name:        str        = "Organization",
    cve_ids:         list[str] | None = None,
    min_year:        int | None = None,
    severities:      list[str] | None = None,
    output_dir:      str | None = None,
    verbose:         bool       = True,
) -> dict:
    """
    Run the full ARIA 10-agent pipeline end to end.

    Args:
        org_description : Plain-English description of the organization.
        org_name        : Display name for the report.
        cve_ids         : Optional list of specific CVE IDs to analyze.
                          If None, uses the full NVD sample.
        min_year        : Only include CVEs published >= this year.
        severities      : Filter to specific severity levels.
        output_dir      : Where to write output files.
        verbose         : Print progress updates.

    Returns:
        Full report dict from Agent 10.
    """
    start_time = time.time()
    _log(verbose, "\n" + "═"*60)
    _log(verbose, "  ARIA — Autonomous Risk Intelligence Agent")
    _log(verbose, "  UMD Agentic AI Challenge 2026")
    _log(verbose, "═"*60 + "\n")

    # ── Stage 0: Business Context (runs once, used by multiple agents) ────────
    _log(verbose, "Stage 0 — Parsing business context…")
    try:
        business_context = a4.run(org_description, org_name)
    except Exception as e:
        _log(verbose, f"  ⚠ Agent 4 error: {e} — using defaults")
        business_context = _default_business_context(org_name)

    # ── Stage 1: CVE Ingestion ────────────────────────────────────────────────
    _log(verbose, "Stage 1 — Ingesting CVEs from NVD…")
    try:
        cve_records = a1.run(cve_ids=cve_ids, min_year=min_year, severities=severities)
    except Exception as e:
        raise RuntimeError(f"Agent 1 (CVE Ingestion) failed: {e}") from e

    if not cve_records:
        _log(verbose, "No CVEs returned by Agent 1. Check filters.")
        return {"error": "No CVEs ingested", "records": []}

    # ── Stage 2+3: Exploit Intel + Threat Context (parallel) ─────────────────
    _log(verbose, "Stage 2+3 — Exploit intelligence + MITRE mapping (parallel)…")
    exploit_records = threat_records = None

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_exploit = pool.submit(a2.run, cve_records)
        f_threat  = pool.submit(a3.run, cve_records)

        try:
            exploit_records = f_exploit.result()
        except Exception as e:
            _log(verbose, f"  ⚠ Agent 2 error: {e} — EPSS/KEV defaulted to 0")
            exploit_records = _apply_defaults(cve_records, {
                "epss": 0.00197, "epss_tier": "MINIMAL", "in_kev": False,
                "ransomware": False, "exploit_priority": "LOW",
                "kev_vendor": "", "kev_due_date": "", "kev_days_to_remediate": None,
                "kev_description": ""
            })

        try:
            threat_records_map = {r["cve_id"]: r for r in f_threat.result()}
        except Exception as e:
            _log(verbose, f"  ⚠ Agent 3 error: {e} — MITRE context defaulted")
            threat_records_map = {}

    # Merge exploit + threat results onto same records
    threat_fields = ["mitre_tactics", "mitre_techniques", "primary_tactic",
                     "attack_phase", "technique_count", "threat_context"]
    merged = []
    for rec in exploit_records:
        rec = dict(rec)
        threat_rec = threat_records_map.get(rec["cve_id"], {})
        for field in threat_fields:
            rec[field] = threat_rec.get(field, _threat_defaults().get(field))
        merged.append(rec)
    cve_records = merged

    # ── Stage 4: Asset Matching ───────────────────────────────────────────────
    _log(verbose, "Stage 4 — Matching CVEs to assets…")
    try:
        cve_records = a5.run(cve_records, business_context)
    except Exception as e:
        _log(verbose, f"  ⚠ Agent 5 error: {e} — assets defaulted")
        cve_records = _apply_defaults(cve_records, {
            "matched_assets": [], "worst_asset": {}, "asset_name": "Unknown",
            "criticality": "medium", "internet_facing": False,
            "asset_match_method": "none", "asset_match_confidence": "NONE"
        })

    # ── Stage 5+6: Compliance + Blast Radius (parallel) ──────────────────────
    _log(verbose, "Stage 5+6 — Compliance impact + blast radius (parallel)…")

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_compliance = pool.submit(a6.run, cve_records, business_context)
        f_blast      = pool.submit(a7.run, cve_records)

        compliance_map = {}
        blast_map      = {}

        try:
            for r in f_compliance.result():
                compliance_map[r["cve_id"]] = r
        except Exception as e:
            _log(verbose, f"  ⚠ Agent 6 error: {e} — compliance defaulted")

        try:
            for r in f_blast.result():
                blast_map[r["cve_id"]] = r
        except Exception as e:
            _log(verbose, f"  ⚠ Agent 7 error: {e} — blast radius defaulted")

    # Merge compliance + blast radius
    compliance_fields = ["compliance_fine", "compliance_flags",
                         "compliance_breakdown", "compliance_reasoning"]
    blast_fields      = ["blast_radius", "blast_radius_count", "blast_path",
                         "blast_label", "blast_context"]
    merged = []
    for rec in cve_records:
        rec = dict(rec)
        cid = rec["cve_id"]
        for f in compliance_fields:
            rec[f] = compliance_map.get(cid, {}).get(f, _compliance_defaults()[f])
        for f in blast_fields:
            rec[f] = blast_map.get(cid, {}).get(f, _blast_defaults()[f])
        merged.append(rec)
    cve_records = merged

    # ── Stage 7: Patch Feasibility ────────────────────────────────────────────
    _log(verbose, "Stage 7 — Checking patch availability…")
    try:
        cve_records = a8.run(cve_records)
    except Exception as e:
        _log(verbose, f"  ⚠ Agent 8 error: {e} — patch status defaulted")
        cve_records = _apply_defaults(cve_records, {
            "patch_available": None, "patch_version": "", "patch_source": "Unknown",
            "patch_url": "", "patch_conflict": False, "patch_conflict_note": "",
            "patch_action": "UNKNOWN — Check vendor advisory",
            "patch_context": "Patch status unavailable — check vendor."
        })

    # ── Stage 8: ROI Calculation ──────────────────────────────────────────────
    _log(verbose, "Stage 8 — Computing ROI…")
    try:
        cve_records = a9.run(cve_records, business_context)
    except Exception as e:
        _log(verbose, f"  ⚠ Agent 9 error: {e} — ROI defaulted")
        cve_records = _apply_defaults(cve_records, {
            "base_score": 0.0, "final_score": 0.0,
            "roi_patch_cost": 0, "roi_breach_risk": 0, "roi_net_benefit": 0,
            "roi_annual_savings": 0, "roi_payback_days": 365, "roi_vs_manual": 0,
            "roi_recommendation": "Unknown", "roi_summary": "ROI unavailable",
            "aria_reasoning": []
        })

    # ── Stage 8b: Claude Final Triage Validation ──────────────────────────────
    _log(verbose, "Stage 8b — Claude triage validation (top-5 sanity check)…")
    triage_note = _claude_triage_validation(cve_records[:5], business_context, verbose)
    if triage_note:
        _log(verbose, f"  Claude: {triage_note[:120]}…")

    # ── Stage 9: Report Generation ────────────────────────────────────────────
    _log(verbose, "Stage 9 — Generating report…")
    try:
        report = a10.run(cve_records, business_context, output_dir=output_dir)
    except Exception as e:
        raise RuntimeError(f"Agent 10 (Report Generation) failed: {e}") from e

    report["triage_validation"] = triage_note

    elapsed = time.time() - start_time
    _log(verbose, f"\n✓ ARIA pipeline complete in {elapsed:.1f}s")
    _log(verbose, f"  {len(cve_records)} CVEs analyzed")
    _log(verbose, "═"*60 + "\n")

    return report


# ── Claude triage validation ─────────────────────────────────────────────────

def _claude_triage_validation(
    top5:             list[dict],
    business_context: dict,
    verbose:          bool,
) -> str:
    """
    Uses Claude to sanity-check the top-5 CVEs and produce a single
    plain-English triage recommendation for the security team.
    Returns empty string if Claude is unavailable.
    """
    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return ""

        client = anthropic.Anthropic(api_key=api_key)

        org_name   = business_context.get("org_name", "the organization")
        industry   = business_context.get("industry", "Unknown")
        compliance = []
        if business_context.get("handles_payments"):    compliance.append("PCI DSS")
        if business_context.get("handles_health_data"): compliance.append("HIPAA")
        if business_context.get("is_technology_company"): compliance.append("SOC2")

        cve_summaries = []
        for i, r in enumerate(top5, 1):
            cve_summaries.append(
                f"#{i} {r['cve_id']}: CVSS={r.get('cvss','N/A')}, "
                f"EPSS={r.get('epss',0):.3f}, KEV={r.get('in_kev',False)}, "
                f"Ransomware={r.get('ransomware',False)}, "
                f"Asset={r.get('asset_name','Unknown')} ({r.get('criticality','?')}), "
                f"FinalScore={r.get('final_score',0):.2f}, "
                f"ROI=${r.get('roi_net_benefit',0):,.0f}"
            )

        prompt = f"""You are ARIA, a senior AI security analyst reviewing an automated vulnerability prioritization for {org_name} ({industry} industry, compliance: {', '.join(compliance) or 'none'}).

The automated system ranked these as the top-5 CVEs to patch:

{chr(10).join(cve_summaries)}

In 2-3 sentences: Does this ranking look correct? What is the single most important action the security team should take TODAY? Flag any concerns."""

        resp = client.messages.create(
            model      = "claude-sonnet-4-5",
            max_tokens = 250,
            messages   = [{"role": "user", "content": prompt}],
        )
        return resp.content[0].text.strip()

    except Exception as e:
        if verbose:
            print(f"  [Orchestrator] Claude triage skipped: {e}")
        return ""


# ── Defaults used when an agent fails ────────────────────────────────────────

def _default_business_context(org_name: str) -> dict:
    return {
        "org_name": org_name, "industry": "Unknown", "revenue_tier": "smb",
        "employee_count": None, "handles_payments": False,
        "handles_health_data": False, "is_technology_company": True,
        "handles_eu_data": False, "uses_windows": True, "uses_cloud": False,
        "uses_open_source": True, "primary_stack": [],
        "breach_cost_estimate": 4_880_000, "risk_tolerance": "medium",
        "raw_description": ""
    }

def _threat_defaults() -> dict:
    return {
        "mitre_tactics": ["Unknown"], "mitre_techniques": [],
        "primary_tactic": "Unknown", "attack_phase": "Attack Phase Unknown",
        "technique_count": 0, "threat_context": ""
    }

def _compliance_defaults() -> dict:
    return {
        "compliance_fine": 0.0, "compliance_flags": [],
        "compliance_breakdown": {}, "compliance_reasoning": []
    }

def _blast_defaults() -> dict:
    return {
        "blast_radius": 0.0, "blast_radius_count": 0, "blast_path": [],
        "blast_label": "NONE", "blast_context": ""
    }

def _apply_defaults(records: list[dict], defaults: dict) -> list[dict]:
    return [{**rec, **{k: v for k, v in defaults.items() if k not in rec}}
            for rec in records]


def _log(verbose: bool, msg: str) -> None:
    if verbose:
        print(msg)
