"""
agent_10_report.py — Report Generation Agent
Responsibility: Take fully-scored CVE records and produce a ranked,
plain-English prioritization report for three audiences:
  1. Security team     — actionable ranked patch list with technical detail
  2. Management        — executive summary with dollar ROI
  3. Audit trail       — machine-readable JSON with full reasoning

LLM USAGE: Claude (claude-sonnet-4-5) generates the natural language reasoning
for the top-10 CVEs. This is the RIGHT place for LLM because:
  - Combining 8 signals (CVSS, EPSS, KEV, ransomware, asset criticality, blast
    radius, compliance, ROI) into a coherent English sentence is exactly what
    LLMs do well — and exactly what humans need to act on a recommendation.
  - Template strings produce mechanical, repetitive text. Claude produces
    context-sensitive reasoning that varies based on what's actually dangerous.
  - Security analysts need to understand WHY a CVE is ranked #1, not just see
    numbers. Claude bridges the gap between data and decision.

FALLBACK: If ANTHROPIC_API_KEY is not set, structured template reasoning is used.
All scores, tiers, and rankings are computed deterministically regardless.

WHY NOT OTHER AGENTS:
  - Agents 1–9 process structured data where determinism and auditability matter.
    An LLM choosing EPSS weights or CWE mappings would be unpredictable and
    unauditable — unacceptable for a security-critical pipeline.
  - Agent 10 is the human-facing output layer. This is where natural language
    genuinely adds value: making data comprehensible to people.

Input:  scored CVE records (from Agent 9) + business_context dict
Output: writes report files and returns report dict
"""

from __future__ import annotations
import json, os, re
from datetime import datetime
from typing import Optional

from agents.shared.scheduler import build_schedule, format_schedule_markdown

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── Priority tier labels ───────────────────────────────────────────────────────
TIER_LABELS = {
    1: "🔴 TIER 1 — PATCH IMMEDIATELY (within 24 hours)",
    2: "🟠 TIER 2 — PATCH URGENTLY (within 7 days)",
    3: "🟡 TIER 3 — PATCH THIS SPRINT (within 30 days)",
    4: "⚪ TIER 4 — MONITOR (patch when convenient)",
}

TIER_COLORS = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


def run(
    cve_records:      list[dict],
    business_context: dict,
    output_dir:       Optional[str] = None,
    triage_note:      Optional[str] = None,
) -> dict:
    """
    Generate the full ARIA prioritization report.

    Returns a report dict with:
      - metadata        : run info, org info, timestamp
      - executive_summary: 5-bullet CFO summary
      - tier1/2/3/4     : ranked CVE lists by priority tier
      - top10           : top 10 CVEs with full reasoning
      - audit_trail     : complete scored record for every CVE
      - files_written   : list of output file paths
    """
    if output_dir is None:
        output_dir = os.path.join(BASE, "output")
    os.makedirs(output_dir, exist_ok=True)

    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    org_name   = business_context.get("org_name", "Organization")
    run_date   = datetime.now().strftime("%B %d, %Y at %H:%M")

    # ── Assign priority tiers ─────────────────────────────────────────────────
    tiered = _assign_tiers(cve_records)

    # ── Executive summary ─────────────────────────────────────────────────────
    exec_summary = _build_executive_summary(cve_records, business_context, tiered)

    # ── Top-10 detailed section ───────────────────────────────────────────────
    top10 = _build_top10(cve_records[:10], business_context)

    # ── Maintenance-window patch schedule ─────────────────────────────────────
    schedule = build_schedule(cve_records, business_context)

    # ── Full report dict ──────────────────────────────────────────────────────
    report = {
        "metadata": {
            "generated_by":  "ARIA — Autonomous Risk Intelligence Agent",
            "version":       "1.1",
            "run_date":      run_date,
            "org_name":      org_name,
            "total_cves":    len(cve_records),
            "industry":      business_context.get("industry", "Unknown"),
            "compliance":    _compliance_list(business_context),
        },
        "executive_summary":  exec_summary,
        "triage_note":        triage_note or "",
        "patch_schedule":     {
            "summary":        schedule.summary,
            "scheduled_cves": schedule.scheduled_cves,
            "backlog_cves":   schedule.backlog_cves,
            "total_labor_cost": schedule.total_labor_cost,
            "total_roi":      schedule.total_roi,
            "batches": [
                {
                    "window":    b.window_label,
                    "date":      b.scheduled_date,
                    "cves":      b.cve_ids,
                    "hours":     b.engineer_hours,
                    "budget_h":  b.budget_hours,
                    "labor_$":   b.labor_cost,
                    "roi_$":     b.net_roi,
                    "notes":     b.notes,
                }
                for b in schedule.batches
            ],
            "backlog": schedule.backlog[:20],
        },
        "tier1_immediate":    tiered[1],
        "tier2_urgent":       tiered[2],
        "tier3_sprint":       tiered[3],
        "tier4_monitor":      tiered[4],
        "top10_detailed":     top10,
        "audit_trail":        _build_audit_trail(cve_records),
        "_schedule_obj":      schedule,   # raw object for markdown rendering
    }

    # ── Write files ───────────────────────────────────────────────────────────
    files = []

    # 1. Human-readable Markdown report
    md_path = os.path.join(output_dir, f"aria_report_{timestamp}.md")
    with open(md_path, "w") as f:
        f.write(_render_markdown(report, org_name, run_date))
    files.append(md_path)

    # 2. Machine-readable JSON (audit trail + full data)
    json_path = os.path.join(output_dir, f"aria_audit_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    files.append(json_path)

    # 3. Quick CSV for spreadsheet import
    csv_path = os.path.join(output_dir, f"aria_ranked_{timestamp}.csv")
    _write_csv(cve_records, csv_path)
    files.append(csv_path)

    report["files_written"] = files

    _print_summary(report, files)
    return report


# ── Tier assignment ────────────────────────────────────────────────────────────

def _assign_tiers(records: list[dict]) -> dict:
    tiers = {1: [], 2: [], 3: [], 4: []}
    for rec in records:
        tier = _get_tier(rec)
        tiers[tier].append(_tier_entry(rec, tier))
    return tiers


def _get_tier(rec: dict) -> int:
    """
    Tier assignment uses BOTH signal quality AND final score thresholds.
    This prevents all CVEs from collapsing into Tier 2 due to criticality alone.

    Tier 1 (patch in 24h):
      - Any CVE on CISA KEV (confirmed active exploitation), OR
      - Ransomware-linked CVE, OR
      - EPSS ≥ 0.50 on an internet-facing critical asset (final_score ≥ 5.0)

    Tier 2 (patch in 7 days):
      - HIGH exploit priority (EPSS ≥ 0.50), OR
      - final_score ≥ 3.0 with a confirmed asset match

    Tier 3 (patch this sprint — 30 days):
      - MEDIUM exploit priority (EPSS ≥ 0.10), OR
      - final_score ≥ 1.5, OR
      - compliance fine > $50K with asset match

    Tier 4 (monitor):
      - Everything else — low EPSS, no asset match, or no exploit signal
    """
    final_score = rec.get("final_score", 0.0)
    has_asset   = bool(rec.get("matched_assets"))

    # Tier 1: confirmed/imminent exploitation
    if rec.get("in_kev") or rec.get("ransomware"):
        return 1
    if rec.get("epss", 0) >= 0.50 and rec.get("internet_facing") and rec.get("criticality") == "critical":
        return 1

    # Tier 2: high exploit signal or high final score with real asset match
    if rec.get("exploit_priority") == "HIGH":
        return 2
    if has_asset and final_score >= 3.0:
        return 2

    # Tier 3: medium signal or moderate score
    if rec.get("exploit_priority") == "MEDIUM":
        return 3
    if has_asset and final_score >= 1.5:
        return 3
    if has_asset and rec.get("compliance_fine", 0) > 50_000 and rec.get("cvss", 0) >= 7.0:
        return 3

    # Tier 4: deprioritize
    return 4


def _tier_entry(rec: dict, tier: int) -> dict:
    return {
        "rank":           rec.get("_rank", 0),
        "cve_id":         rec["cve_id"],
        "cvss":           rec.get("cvss"),
        "epss":           rec.get("epss"),
        "in_kev":         rec.get("in_kev"),
        "ransomware":     rec.get("ransomware"),
        "asset":          rec.get("asset_name", ""),
        "criticality":    rec.get("criticality", ""),
        "compliance_fine":rec.get("compliance_fine", 0),
        "patch_action":   rec.get("patch_action", ""),
        "roi_net_benefit":rec.get("roi_net_benefit", 0),
        "final_score":    rec.get("final_score", 0),
        "attack_phase":   rec.get("attack_phase", ""),
    }


# ── Executive summary ──────────────────────────────────────────────────────────

def _build_executive_summary(
    records:  list[dict],
    ctx:      dict,
    tiered:   dict,
) -> dict:
    total          = len(records)
    tier1_count    = len(tiered[1])
    tier2_count    = len(tiered[2])
    kev_count      = sum(1 for r in records if r.get("in_kev"))
    rw_count       = sum(1 for r in records if r.get("ransomware"))
    total_risk     = sum(r.get("roi_breach_risk", 0) for r in records)
    total_fine     = sum(r.get("compliance_fine", 0) for r in records)
    top_roi        = max(records, key=lambda r: r.get("roi_net_benefit", 0), default={})
    manual_savings = sum(r.get("roi_vs_manual", 0) for r in records[:50])  # vs manual triage of top 50

    return {
        "headline": (
            f"ARIA analyzed {total} CVEs for {ctx.get('org_name','your organization')}. "
            f"{tier1_count} require patching within 24 hours. "
            f"{tier2_count} require patching within 7 days."
        ),
        "bullets": [
            f"{kev_count} CVEs are on the CISA Known Exploited Vulnerabilities list — "
            f"attackers are actively exploiting these right now.",
            f"{rw_count} CVEs are used in ransomware campaigns. "
            f"Average ransomware incident cost: $1–5 million.",
            f"Total breach risk exposure across all CVEs: ${total_risk:,.0f}.",
            f"Total regulatory fine exposure (PCI/HIPAA/SOC2): ${total_fine:,.0f}.",
            f"Highest single-CVE ROI: patching {top_roi.get('cve_id','')} prevents "
            f"~${top_roi.get('roi_breach_risk',0):,.0f} in expected breach cost "
            f"for ${top_roi.get('roi_patch_cost',0):,} engineering cost.",
            f"ARIA vs. manual triage savings: ~${manual_savings:,.0f} in analyst hours "
            f"(top 50 CVEs evaluated).",
        ],
        "immediate_action": (
            f"Patch {tier1_count} Tier 1 CVEs NOW. "
            f"Schedule {tier2_count} Tier 2 CVEs in the current sprint."
        ),
        "kev_count":    kev_count,
        "rw_count":     rw_count,
        "tier1_count":  tier1_count,
        "tier2_count":  tier2_count,
        "total_risk":   total_risk,
        "total_fine":   total_fine,
    }


# ── Claude reasoning for top CVEs ────────────────────────────────────────────

_REASONING_SYSTEM = """You are ARIA, an AI vulnerability prioritization analyst.
Given structured data about a CVE (vulnerability) and the organization it affects,
write a concise 2-3 sentence plain-English justification explaining WHY this CVE
is ranked where it is and what the security team should do. Be specific, use the
actual numbers provided, and write for a mixed technical/management audience.
Never use bullet points — write flowing prose."""

def _claude_reasoning(rec: dict, rank: int, org_name: str) -> Optional[str]:
    """Use Claude to generate natural language reasoning for one CVE. Returns None on failure."""
    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return None
        client = anthropic.Anthropic(api_key=api_key)

        prompt = f"""Rank #{rank} CVE for {org_name}:

CVE ID: {rec['cve_id']}
CVSS Score: {rec.get('cvss', 'N/A')} / 10
EPSS Score: {rec.get('epss', 0):.4f} ({rec.get('epss',0)*100:.1f}% chance of exploitation in 30 days)
On CISA KEV (confirmed active exploitation): {rec.get('in_kev', False)}
Ransomware-linked: {rec.get('ransomware', False)}
Attack phase this enables: {rec.get('attack_phase', 'Unknown')}
Matched asset: {rec.get('asset_name', 'Unknown')} (criticality: {rec.get('criticality','unknown')}, internet-facing: {rec.get('internet_facing', False)})
Blast radius: {rec.get('blast_radius_count', 0)} downstream services at risk
Compliance fine exposure: ${rec.get('compliance_fine', 0):,.0f}
Patch action: {rec.get('patch_action', 'Unknown')}
ROI of patching: ${rec.get('roi_net_benefit', 0):,.0f} net benefit

Write the 2-3 sentence justification for why this CVE is rank #{rank}:"""

        resp = client.messages.create(
            model      = "claude-sonnet-4-5",
            max_tokens = 200,
            system     = _REASONING_SYSTEM,
            messages   = [{"role": "user", "content": prompt}],
        )
        return resp.content[0].text.strip()
    except Exception:
        return None


def _template_reasoning(rec: dict, rank: int) -> str:
    """Fallback structured reasoning when Claude is not available."""
    parts = []
    if rec.get("in_kev"):
        parts.append(f"{rec['cve_id']} is confirmed actively exploited (CISA KEV)")
    if rec.get("ransomware"):
        parts.append("used in ransomware campaigns")
    if rec.get("epss", 0) >= 0.1:
        parts.append(f"EPSS {rec['epss']:.3f} ({rec['epss']*100:.1f}% exploitation probability)")
    if rec.get("internet_facing") and rec.get("criticality") == "critical":
        parts.append(f"affects critical internet-facing asset '{rec.get('asset_name','')}'")
    if rec.get("compliance_fine", 0) > 0:
        parts.append(f"${rec['compliance_fine']:,.0f} compliance fine exposure")

    summary = "; ".join(parts) if parts else f"CVSS {rec.get('cvss','N/A')}"
    action  = rec.get("patch_action", "Review vendor advisory")
    roi     = rec.get("roi_net_benefit", 0)
    return (f"Ranked #{rank}: {summary}. "
            f"Recommended action: {action}. "
            f"Net ROI of patching: ${roi:,.0f}.")


# ── Top-10 detailed ────────────────────────────────────────────────────────────

def _build_top10(records: list[dict], ctx: dict) -> list[dict]:
    org_name = ctx.get("org_name", "the organization")
    result   = []
    for i, rec in enumerate(records, 1):
        # Generate LLM reasoning (falls back to template if Claude unavailable)
        llm_reason = _claude_reasoning(rec, i, org_name)
        reasoning  = llm_reason if llm_reason else _template_reasoning(rec, i)

        entry = {
            "rank":            i,
            "cve_id":          rec["cve_id"],
            "llm_reasoning":   reasoning,   # ← Claude-generated or template fallback
            "final_score":     rec.get("final_score"),
            "base_score":      rec.get("base_score"),
            "cvss":            rec.get("cvss"),
            "severity":        rec.get("severity"),
            "epss":            rec.get("epss"),
            "in_kev":          rec.get("in_kev"),
            "ransomware":      rec.get("ransomware"),
            "exploit_priority":rec.get("exploit_priority"),
            "attack_phase":    rec.get("attack_phase"),
            "cwe":             rec.get("cwe"),
            "asset_name":      rec.get("asset_name"),
            "criticality":     rec.get("criticality"),
            "internet_facing": rec.get("internet_facing"),
            "compliance_fine": rec.get("compliance_fine"),
            "compliance_flags":rec.get("compliance_flags"),
            "blast_radius":    rec.get("blast_radius"),
            "blast_label":     rec.get("blast_label"),
            "patch_action":    rec.get("patch_action"),
            "patch_source":    rec.get("patch_source"),
            "patch_conflict":  rec.get("patch_conflict"),
            "patch_conflict_note": rec.get("patch_conflict_note", ""),
            "roi_patch_cost":  rec.get("roi_patch_cost"),
            "roi_breach_risk": rec.get("roi_breach_risk"),
            "roi_net_benefit": rec.get("roi_net_benefit"),
            "roi_summary":     rec.get("roi_summary"),
            "confidence":      rec.get("confidence", "LOW"),
            "confidence_score":rec.get("confidence_score", 0.0),
            "reasoning":       rec.get("aria_reasoning", []),
            "threat_context":  rec.get("threat_context", ""),
            "patch_context":   rec.get("patch_context", ""),
            "blast_context":   rec.get("blast_context", ""),
        }
        result.append(entry)
    return result


# ── Audit trail ────────────────────────────────────────────────────────────────

def _build_audit_trail(records: list[dict]) -> list[dict]:
    """Lightweight audit record for every CVE — stripped of large fields."""
    trail = []
    for i, rec in enumerate(records, 1):
        trail.append({
            "rank":           i,
            "cve_id":         rec["cve_id"],
            "final_score":    rec.get("final_score"),
            "base_score":     rec.get("base_score"),
            "epss":           rec.get("epss"),
            "cvss":           rec.get("cvss"),
            "in_kev":         rec.get("in_kev"),
            "ransomware":     rec.get("ransomware"),
            "exploit_priority": rec.get("exploit_priority"),
            "asset_name":     rec.get("asset_name"),
            "criticality":    rec.get("criticality"),
            "internet_facing":rec.get("internet_facing"),
            "blast_radius":   rec.get("blast_radius"),
            "compliance_fine":rec.get("compliance_fine"),
            "compliance_flags":rec.get("compliance_flags", []),
            "patch_action":    rec.get("patch_action"),
            "roi_net_benefit": rec.get("roi_net_benefit"),
            "confidence":      rec.get("confidence", "LOW"),
            "confidence_score":rec.get("confidence_score", 0.0),
        })
    return trail


# ── Markdown renderer ─────────────────────────────────────────────────────────

def _render_markdown(report: dict, org_name: str, run_date: str) -> str:
    es    = report["executive_summary"]
    t1    = report["tier1_immediate"]
    t2    = report["tier2_urgent"]
    top10 = report["top10_detailed"]
    meta  = report["metadata"]
    sched = report.get("_schedule_obj")
    tnote = report.get("triage_note", "")

    lines = []
    lines.append("# ARIA Vulnerability Prioritization Report")
    lines.append(f"**Organization:** {org_name}  |  **Generated:** {run_date}")
    lines.append(f"**Total CVEs analyzed:** {meta['total_cves']}  |  "
                 f"**Industry:** {meta['industry']}  |  "
                 f"**Compliance:** {', '.join(meta['compliance']) or 'None'}")
    lines.append(f"**ARIA Version:** {meta.get('version','1.1')}  |  "
                 f"**System:** Autonomous Risk Intelligence Agent — 10-Agent Pipeline")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"> {es['headline']}")
    lines.append("")
    for b in es["bullets"]:
        lines.append(f"- {b}")
    lines.append("")
    lines.append(f"**Immediate action required:** {es['immediate_action']}")
    lines.append("")

    # Claude triage note (orchestrator sanity check)
    if tnote:
        lines.append("> **Senior Analyst AI Review (Claude Sonnet):**")
        lines.append(f"> {tnote}")
        lines.append("")

    lines.append("---")
    lines.append("")

    # Tier 1 — full action, no truncation, add confidence
    lines.append(f"## {TIER_LABELS[1]}")
    lines.append("")
    if t1:
        lines.append("| Rank | CVE ID | CVSS | EPSS | KEV | RW | Asset | Fine $ | Net ROI | Action |")
        lines.append("|------|--------|------|------|-----|----|-------|--------|---------|--------|")
        for i, r in enumerate(t1, 1):
            lines.append(
                f"| {i} | {r['cve_id']} | {r['cvss'] or 'N/A'} | "
                f"{r['epss']:.3f} | {'✓' if r['in_kev'] else ''} | "
                f"{'✓' if r['ransomware'] else ''} | "
                f"{(r['asset'] or 'No match')[:30]} | "
                f"${r['compliance_fine']:,.0f} | "
                f"${r['roi_net_benefit']:,.0f} | "
                f"{r['patch_action']} |"
            )
    else:
        lines.append("*No Tier 1 CVEs in this batch.*")
    lines.append("")

    # Tier 2 — full action, no truncation
    lines.append(f"## {TIER_LABELS[2]}")
    lines.append("")
    if t2:
        lines.append("| Rank | CVE ID | CVSS | EPSS | Asset | Net ROI | Action |")
        lines.append("|------|--------|------|------|-------|---------|--------|")
        for i, r in enumerate(t2, 1):
            lines.append(
                f"| {i} | {r['cve_id']} | {r['cvss'] or 'N/A'} | "
                f"{r['epss']:.3f} | "
                f"{(r['asset'] or 'No match')[:30]} | "
                f"${r['roi_net_benefit']:,.0f} | "
                f"{r['patch_action']} |"
            )
    else:
        lines.append("*No Tier 2 CVEs in this batch.*")
    lines.append("")

    # Maintenance window schedule (NEW — closes problem statement gap)
    if sched:
        lines.append(format_schedule_markdown(sched))

    # Top 10 detailed
    lines.append("---")
    lines.append("")
    lines.append("## Top 10 CVEs — Full ARIA Analysis")
    lines.append("")
    for r in top10:
        kev_badge = "🔴 KEV" if r["in_kev"] else ""
        rw_badge  = "☠ RW"  if r["ransomware"] else ""
        badges    = " ".join(b for b in [kev_badge, rw_badge] if b)
        lines.append(f"### #{r['rank']} — {r['cve_id']}  {badges}")
        lines.append(
            f"**ARIA Score:** {r['final_score']} | "
            f"**CVSS:** {r['cvss'] or 'N/A'} | "
            f"**EPSS:** {r['epss']:.4f} ({r.get('epss',0)*100:.1f}%) | "
            f"**KEV:** {'YES' if r['in_kev'] else 'No'} | "
            f"**Ransomware:** {'YES' if r['ransomware'] else 'No'} | "
            f"**Confidence:** {r.get('confidence','?')}"
        )
        lines.append(
            f"**Asset:** {r['asset_name'] or 'No direct match'} | "
            f"**Criticality:** {r['criticality']} | "
            f"**Internet-facing:** {r['internet_facing']}"
        )
        lines.append(f"**Attack Phase:** {r['attack_phase']}")
        lines.append(
            f"**Compliance Exposure:** ${r['compliance_fine']:,.0f} "
            f"({', '.join(r['compliance_flags'] or ['None'])})"
        )
        lines.append(f"**ROI Summary:** {r['roi_summary']}")
        lines.append(f"**Patch Action:** {r['patch_action']}")
        lines.append("")
        if r.get("llm_reasoning"):
            lines.append("**Why ARIA ranks this here (AI reasoning):**")
            lines.append(f"> {r['llm_reasoning']}")
        else:
            lines.append("**Why ARIA ranks this here:**")
            for bullet in (r.get("reasoning") or []):
                lines.append(f"- {bullet}")
        lines.append("")
        if r["threat_context"]:
            lines.append(f"*Threat context:* {r['threat_context']}")
        if r["blast_context"]:
            lines.append(f"*Blast radius:* {r['blast_context']}")
        if r["patch_context"]:
            lines.append(f"*Patch status:* {r['patch_context']}")
        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("*Report generated by ARIA — Autonomous Risk Intelligence Agent*")
    lines.append("*UMD Agentic AI Challenge 2026 — System recommends, humans decide.*")

    return "\n".join(lines)


# ── CSV writer ────────────────────────────────────────────────────────────────

def _write_csv(records: list[dict], path: str) -> None:
    import csv
    fields = [
        "rank", "cve_id", "final_score", "base_score", "cvss", "epss",
        "in_kev", "ransomware", "exploit_priority",
        "asset_name", "criticality", "internet_facing",
        "compliance_fine", "blast_radius", "patch_action",
        "roi_patch_cost", "roi_breach_risk", "roi_net_benefit",
        "confidence", "confidence_score",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for i, rec in enumerate(records, 1):
            row = {"rank": i}
            row.update(rec)
            writer.writerow(row)


def _compliance_list(ctx: dict) -> list:
    flags = []
    if ctx.get("handles_payments"):    flags.append("PCI DSS")
    if ctx.get("handles_health_data"): flags.append("HIPAA")
    if ctx.get("is_technology_company"): flags.append("SOC2")
    if ctx.get("handles_eu_data"):     flags.append("GDPR")
    return flags


def _print_summary(report: dict, files: list) -> None:
    es = report["executive_summary"]
    print(f"\n[Agent 10] Report generated:")
    print(f"  {es['headline']}")
    print(f"  Tier 1 (24h)  : {es['tier1_count']} CVEs")
    print(f"  Tier 2 (7d)   : {es['tier2_count']} CVEs")
    print(f"  KEV confirmed : {es['kev_count']}")
    print(f"  Ransomware    : {es['rw_count']}")
    print(f"  Files written :")
    for f in files:
        print(f"    {f}")
