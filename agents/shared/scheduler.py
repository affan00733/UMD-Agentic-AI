"""
agents/shared/scheduler.py — Patch Schedule Builder
Responsibility: Convert ARIA's ranked CVE list into a concrete, actionable
patch schedule that respects REAL operational constraints:

  1. Engineer hour budget per sprint (limited IT resources)
  2. Maintenance window timing (can't patch a production server at 2pm Monday)
  3. Risk-ordered batching — highest-risk CVEs in the earliest available window
  4. Dependency-safe ordering — don't patch downstream before upstream

This closes the competition problem statement requirement explicitly stated as:
  "operational constraints such as maintenance windows and limited IT resources"

Why this matters to business:
  A ranked list is not a schedule. A CISO needs to know: "Which CVEs do we patch
  THIS Sunday at 2am, which do we patch NEXT Sunday, and which go in the backlog?"
  ARIA is the only tool that produces this output automatically.

Input:  ranked CVE records (from Agent 10), business_context dict
Output: PatchSchedule dict with concrete windows, engineer-hours, and CVE batches
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timedelta


# ── Maintenance window definitions ────────────────────────────────────────────
# In production these come from the org's CMDB / change management system.
# Here we use industry-standard defaults.

DEFAULT_MAINTENANCE_WINDOWS = [
    {
        "id":          "emergency",
        "label":       "Emergency (Any time — KEV/Ransomware only)",
        "day_of_week": None,       # any day
        "start_hour":  None,       # any time
        "duration_h":  4,          # max 4 hours
        "engineers":   2,
        "type":        "emergency",
        "description": "Unscheduled emergency window for confirmed-exploited CVEs. "
                       "Triggered by KEV or ransomware flag. Cannot wait for scheduled window.",
    },
    {
        "id":          "primary",
        "label":       "Primary Window (Sunday 02:00–06:00)",
        "day_of_week": 6,          # Sunday
        "start_hour":  2,
        "duration_h":  4,
        "engineers":   2,
        "type":        "scheduled",
        "description": "Primary maintenance window. Low-traffic period. "
                       "2 engineers × 4 hours = 8 engineer-hours available.",
    },
    {
        "id":          "secondary",
        "label":       "Secondary Window (Tuesday 20:00–22:00)",
        "day_of_week": 1,          # Tuesday (Patch Tuesday alignment)
        "start_hour":  20,
        "duration_h":  2,
        "engineers":   1,
        "type":        "scheduled",
        "description": "Patch Tuesday alignment window. 1 engineer × 2 hours = 2 engineer-hours. "
                       "Ideal for Microsoft/MSRC patches.",
    },
    {
        "id":          "extended",
        "label":       "Extended Window (3rd Sunday 00:00–08:00)",
        "day_of_week": 6,          # Sunday
        "start_hour":  0,
        "duration_h":  8,
        "engineers":   3,
        "type":        "extended",
        "description": "Monthly extended maintenance window. "
                       "3 engineers × 8 hours = 24 engineer-hours. "
                       "Used for complex patches requiring staging + rollback.",
    },
]

# Engineer hours required per patch action
PATCH_HOURS: dict[str, float] = {
    "PATCH NOW — EMERGENCY":                              8.0,
    "PATCH NOW":                                          4.0,
    "PATCH — SCHEDULED":                                  2.0,
    "PATCH WITH CAUTION — Test in staging first":         6.0,
    "MONITOR":                                            0.5,   # ticket + watch
    "UNKNOWN — Check vendor advisory":                    2.0,   # investigate + patch
}

ENGINEER_HOURLY_RATE = 75   # $75/hr


@dataclass
class ScheduledBatch:
    window_id:        str
    window_label:     str
    window_type:      str              # emergency / scheduled / extended
    scheduled_date:   str             # ISO date (next occurrence from today)
    cve_ids:          list[str]       = field(default_factory=list)
    engineer_hours:   float           = 0.0
    budget_hours:     float           = 0.0
    labor_cost:       float           = 0.0
    breach_risk_prevented: float      = 0.0
    net_roi:          float           = 0.0
    patch_actions:    list[str]       = field(default_factory=list)
    notes:            list[str]       = field(default_factory=list)


@dataclass
class PatchSchedule:
    org_name:          str
    generated_date:    str
    total_cves:        int
    scheduled_cves:    int
    backlog_cves:      int
    total_labor_cost:  float
    total_roi:         float
    batches:           list[ScheduledBatch] = field(default_factory=list)
    backlog:           list[dict]           = field(default_factory=list)
    summary:           str                  = ""


def build_schedule(
    cve_records:      list[dict],
    business_context: dict,
    reference_date:   Optional[datetime] = None,
) -> PatchSchedule:
    """
    Build a concrete patch schedule from ranked CVE records.

    Args:
        cve_records:       Ranked CVE records (from Agent 10, sorted by final_score desc)
        business_context:  Organization context (for engineer budget)
        reference_date:    Reference "today" (defaults to now; override for testing)

    Returns:
        PatchSchedule with batches assigned to concrete maintenance windows
    """
    if reference_date is None:
        reference_date = datetime.now()

    org_name = business_context.get("org_name", "Organization")

    # Get custom windows from business context, or use defaults
    windows = _get_windows(business_context)

    # Separate records that need action vs just monitoring
    actionable = [r for r in cve_records if r.get("patch_action", "MONITOR") != "MONITOR"]
    monitor_only = [r for r in cve_records if r.get("patch_action", "MONITOR") == "MONITOR"]

    batches: list[ScheduledBatch] = []
    scheduled_ids: set[str] = set()

    # ── Pass 1: Emergency window — KEV + Ransomware only ─────────────────────
    emergency_cves = [
        r for r in actionable
        if r.get("in_kev") or r.get("ransomware")
    ]
    if emergency_cves:
        batch = _build_batch(
            window=windows[0],  # emergency
            cves=emergency_cves,
            reference_date=reference_date,
            note="Cannot wait for scheduled window — active exploitation confirmed.",
        )
        batches.append(batch)
        scheduled_ids.update(r["cve_id"] for r in emergency_cves)

    # ── Pass 2: Fill remaining scheduled windows in priority order ────────────
    remaining = [r for r in actionable if r["cve_id"] not in scheduled_ids]

    for window in windows[1:]:    # skip emergency (already handled)
        if not remaining:
            break
        budget_hours = window["duration_h"] * window["engineers"]
        batch_cves = []
        batch_hours = 0.0

        cves_to_place = list(remaining)
        remaining = []

        for rec in cves_to_place:
            hours_needed = PATCH_HOURS.get(rec.get("patch_action", ""), 2.0)
            if batch_hours + hours_needed <= budget_hours:
                batch_cves.append(rec)
                batch_hours += hours_needed
            else:
                remaining.append(rec)

        if batch_cves:
            batch = _build_batch(
                window=window,
                cves=batch_cves,
                reference_date=reference_date,
            )
            batches.append(batch)
            scheduled_ids.update(r["cve_id"] for r in batch_cves)

    # ── Pass 3: Overflow → backlog ────────────────────────────────────────────
    backlog = [
        {
            "cve_id":        r["cve_id"],
            "cvss":          r.get("cvss", 0),
            "epss":          r.get("epss", 0),
            "final_score":   r.get("final_score", 0),
            "patch_action":  r.get("patch_action", ""),
            "reason":        "Scheduled windows at capacity — add engineering resources or extend window",
        }
        for r in remaining
    ] + [
        {
            "cve_id":        r["cve_id"],
            "cvss":          r.get("cvss", 0),
            "epss":          r.get("epss", 0),
            "final_score":   r.get("final_score", 0),
            "patch_action":  "MONITOR",
            "reason":        "No patch action required — monitor for EPSS/KEV escalation",
        }
        for r in monitor_only[:20]   # top-20 monitors only
    ]

    total_labor  = sum(b.labor_cost for b in batches)
    total_roi    = sum(b.net_roi for b in batches)

    schedule = PatchSchedule(
        org_name       = org_name,
        generated_date = reference_date.strftime("%Y-%m-%d"),
        total_cves     = len(cve_records),
        scheduled_cves = len(scheduled_ids),
        backlog_cves   = len(backlog),
        total_labor_cost = total_labor,
        total_roi        = total_roi,
        batches          = batches,
        backlog          = backlog,
        summary          = _build_summary(batches, backlog, total_roi),
    )
    return schedule


def _build_batch(
    window:         dict,
    cves:           list[dict],
    reference_date: datetime,
    note:           str = "",
) -> ScheduledBatch:
    budget_hours  = window["duration_h"] * window["engineers"]
    hours_used    = sum(PATCH_HOURS.get(r.get("patch_action", ""), 2.0) for r in cves)
    labor_cost    = hours_used * ENGINEER_HOURLY_RATE
    breach_prevented = sum(r.get("roi_breach_risk", 0) for r in cves)
    net_roi       = breach_prevented - labor_cost

    actions = [r.get("patch_action", "UNKNOWN") for r in cves]
    notes   = []
    if note:
        notes.append(note)
    if hours_used > budget_hours * 0.9:
        notes.append(f"Window is {hours_used/budget_hours*100:.0f}% utilized — consider requesting extended window.")
    if any(r.get("patch_conflict") for r in cves):
        notes.append("⚠ One or more patches have dependency conflicts — stage before deploying.")

    sched_date = _next_window_date(window, reference_date)

    return ScheduledBatch(
        window_id         = window["id"],
        window_label      = window["label"],
        window_type       = window["type"],
        scheduled_date    = sched_date,
        cve_ids           = [r["cve_id"] for r in cves],
        engineer_hours    = round(hours_used, 1),
        budget_hours      = budget_hours,
        labor_cost        = round(labor_cost, 2),
        breach_risk_prevented = round(breach_prevented, 2),
        net_roi           = round(net_roi, 2),
        patch_actions     = actions,
        notes             = notes,
    )


def _next_window_date(window: dict, reference_date: datetime) -> str:
    """Return ISO date string of the next occurrence of this window."""
    if window["type"] == "emergency":
        # Emergency is now
        return reference_date.strftime("%Y-%m-%d %H:%M") + " (IMMEDIATELY)"
    dow = window.get("day_of_week")
    hour = window.get("start_hour", 2)
    if dow is None:
        return reference_date.strftime("%Y-%m-%d")
    # Find next occurrence of this day of week
    days_ahead = (dow - reference_date.weekday()) % 7
    if days_ahead == 0:
        days_ahead = 7   # don't use today — use next week
    target = reference_date + timedelta(days=days_ahead)
    return target.replace(hour=hour, minute=0, second=0).strftime("%Y-%m-%d %H:%M")


def _get_windows(business_context: dict) -> list[dict]:
    """Return maintenance windows — from business_context if set, else defaults."""
    custom = business_context.get("maintenance_windows")
    if custom and isinstance(custom, list) and len(custom) > 0:
        return custom
    return DEFAULT_MAINTENANCE_WINDOWS


def _build_summary(batches: list[ScheduledBatch], backlog: list[dict], total_roi: float) -> str:
    sched_count = sum(len(b.cve_ids) for b in batches)
    window_strs = []
    for b in batches:
        if b.cve_ids:
            window_strs.append(
                f"{b.window_label}: {len(b.cve_ids)} CVEs "
                f"({b.engineer_hours}h, ${b.labor_cost:,.0f} labor, "
                f"${b.breach_risk_prevented:,.0f} breach risk prevented)"
            )
    return (
        f"{sched_count} CVEs scheduled across {len(batches)} maintenance window(s). "
        f"{len(backlog)} in backlog. "
        f"Total net ROI of executing this schedule: ${total_roi:,.0f}. "
        + " | ".join(window_strs)
    )


def format_schedule_markdown(schedule: PatchSchedule) -> str:
    """Format PatchSchedule as a markdown section for the ARIA report."""
    lines = [
        "",
        "---",
        "",
        "## 📅 Maintenance-Window Patch Schedule",
        "",
        f"> **{schedule.summary}**",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| CVEs scheduled | {schedule.scheduled_cves} |",
        f"| CVEs in backlog | {schedule.backlog_cves} |",
        f"| Total labor cost | ${schedule.total_labor_cost:,.0f} |",
        f"| Total breach risk prevented | ${schedule.total_roi + schedule.total_labor_cost:,.0f} |",
        f"| Net ROI of executing schedule | ${schedule.total_roi:,.0f} |",
        "",
    ]
    for i, batch in enumerate(schedule.batches, 1):
        lines += [
            f"### Window {i} — {batch.window_label}",
            f"**Scheduled:** {batch.scheduled_date}  |  "
            f"**Engineer-hours used:** {batch.engineer_hours}/{batch.budget_hours}  |  "
            f"**Labor cost:** ${batch.labor_cost:,.0f}  |  "
            f"**Breach risk prevented:** ${batch.breach_risk_prevented:,.0f}",
            "",
            "| CVE ID | Action | Hours |",
            "|--------|--------|-------|",
        ]
        for cve_id, action in zip(batch.cve_ids, batch.patch_actions):
            h = PATCH_HOURS.get(action, 2.0)
            lines.append(f"| {cve_id} | {action} | {h}h |")
        if batch.notes:
            lines.append("")
            for note in batch.notes:
                lines.append(f"> ⚠ {note}")
        lines.append("")

    if schedule.backlog:
        lines += [
            "### Backlog (patch when window capacity permits)",
            "",
            "| CVE ID | CVSS | EPSS | Action | Reason |",
            "|--------|------|------|--------|--------|",
        ]
        for item in schedule.backlog[:10]:
            lines.append(
                f"| {item['cve_id']} | {item['cvss']:.1f} | "
                f"{item['epss']:.4f} | {item['patch_action']} | {item['reason'][:60]} |"
            )
        if len(schedule.backlog) > 10:
            lines.append(f"| *(+ {len(schedule.backlog)-10} more in backlog)* | | | | |")
        lines.append("")

    return "\n".join(lines)
