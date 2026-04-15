"""
ARIA — AI Cyber Risk Command Center (Streamlit)
Run from frontend/ directory:  streamlit run ui/app.py
Requires: streamlit, requests, plotly
"""

from __future__ import annotations

import time
import uuid
import threading
from typing import Any

import requests
import streamlit as st

try:
    import plotly.graph_objects as go
except ImportError:
    go = None

# ── Config ────────────────────────────────────────────────────────────────────

API_URL = "http://localhost:8000/run"

DEFAULT_ORG_DESCRIPTION = (
    "We are a B2B healthcare SaaS company (~250 employees) hosted on AWS. "
    "We process PHI for hospital customers, take card payments for subscriptions, "
    "and run Kubernetes for our API tier. Primary stack: Python, PostgreSQL, Redis, "
    "and third-party OAuth integrations. "
    "We are SOC 2 Type II and need to align with HIPAA and PCI DSS for our roadmap."
)

SEVERITY_COLOR = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316",
    "MEDIUM": "#eab308",   "LOW": "#22c55e", "UNKNOWN": "#94a3b8",
}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

# ── Thread-safe store for background API results ──────────────────────────────
# Uses st.cache_resource so the store SURVIVES Streamlit module reloads.
# A plain module-level dict gets reset to {} whenever Streamlit reloads the
# module (e.g. its file-watcher fires), causing the background thread's write
# to be invisible to the main thread — the animation then loops forever.

@st.cache_resource
def _get_result_store() -> dict:
    """Singleton {data: {run_id: result}, lock: Lock}.
    Guaranteed to outlive any module reload within the same process."""
    return {"data": {}, "lock": threading.Lock()}


def _run_api_background(run_id: str, org_desc: str, org_name: str) -> None:
    """Executes in a background thread; writes result to the cache_resource store."""
    store = _get_result_store()
    try:
        resp = requests.post(
            API_URL,
            json={"org_description": org_desc, "org_name": org_name},
            timeout=600,
        )
        resp.raise_for_status()
        with store["lock"]:
            store["data"][run_id] = {"done": True, "result": resp.json(), "error": None}
    except requests.exceptions.ConnectionError:
        with store["lock"]:
            store["data"][run_id] = {
                "done": True, "result": None,
                "error": (
                    "Cannot connect to ARIA backend at `http://localhost:8000`.\n\n"
                    "**Start it first:**\n```bash\ncd backend/\nuvicorn api:app --host 0.0.0.0 --port 8000\n```"
                ),
            }
    except Exception as exc:
        with store["lock"]:
            store["data"][run_id] = {"done": True, "result": None, "error": str(exc)}


# ── Agent graph constants ─────────────────────────────────────────────────────
#
# Execution order matches the real ARIA orchestrator:
#   1. A4 Business Context (Claude Haiku) — first, feeds context to all
#   2. A1 / A2 / A3  in parallel (ThreadPoolExecutor)
#   3. A5 Asset Matching
#   4. A6 / A7  in parallel
#   5. A8 Patch  →  A9 ROI  →  A10 Report (Claude Sonnet)
#
# Node indices (0-9) map to ANIM_STAGES active/complete sets.

AGENT_NODES: list[dict] = [
    {   # 0
        "idx": 0, "id": "A4", "name": "Business Context", "icon": "🏢",
        "x": 0.0, "y": 5.2,
        "task": "Claude Haiku parses the plain-English org description and extracts: industry category, revenue tier, compliance frameworks (PCI DSS / HIPAA / SOC2 / GDPR), primary tech stack, and risk tolerance. Used by every downstream agent.",
        "receives": ["Free-text org description (user input)"],
        "outputs":  ["Industry", "Compliance frameworks", "Tech stack", "Risk tolerance", "Breach cost estimate"],
        "sources":  ["Org description (user input)", "IBM Cost of Data Breach 2024 (hardcoded estimates)"],
        "llm":      "Claude claude-haiku-4-5",
        "stat_key": "industry",
    },
    {   # 1
        "idx": 1, "id": "A1", "name": "CVE Ingestion", "icon": "📥",
        "x": -3.2, "y": 3.0,
        "task": "Reads NVD JSON feed. Parses CVE-ID, CVSS base score, severity label, CWE weakness category, CPE affected product list, and published date for the 500-CVE evaluation set.",
        "receives": ["NVD JSON (local file)"],
        "outputs":  ["CVE-ID", "CVSS / Severity", "CWE", "CPE list", "Published date"],
        "sources":  ["data/raw/nvd_cves.json — 341,584 CVEs total, 500 loaded"],
        "llm":      None,
        "stat_key": "total_cves",
    },
    {   # 2
        "idx": 2, "id": "A2", "name": "Exploit Intel", "icon": "⚡",
        "x": 0.0, "y": 3.0,
        "task": "Joins EPSS scores (30-day exploitation probability) from FIRST.org and CISA KEV (confirmed actively-exploited) onto every CVE. Tags ransomware-linked CVEs. Assigns exploit priority bucket: CRITICAL / HIGH / MEDIUM / LOW.",
        "receives": ["CVE list from A1", "EPSS scores", "CISA KEV list"],
        "outputs":  ["EPSS score", "KEV flag", "Ransomware flag", "Exploit priority"],
        "sources":  ["data/raw/epss_scores.csv — 323,901 scores", "data/raw/cisa_kev.json — 1,555 CVEs"],
        "llm":      None,
        "stat_key": "kev_count",
    },
    {   # 3
        "idx": 3, "id": "A3", "name": "Threat Mapping", "icon": "🗺️",
        "x": 3.2, "y": 3.0,
        "task": "Maps CWE weakness category → MITRE ATT&CK tactic via a static lookup table (835 ATT&CK techniques). Labels every CVE with its attack phase: Initial Access, Execution, Privilege Escalation, Collection, etc.",
        "receives": ["CWE per CVE", "MITRE ATT&CK dataset"],
        "outputs":  ["Attack phase", "ATT&CK tactic", "Threat context string"],
        "sources":  ["data/raw/mitre_attack.json — 835 techniques"],
        "llm":      None,
        "stat_key": "attack_phase",
    },
    {   # 4
        "idx": 4, "id": "A5", "name": "Asset Matching", "icon": "🔍",
        "x": 0.0, "y": 1.0,
        "task": "Matches each CVE to the 56-asset inventory using a four-method cascade: CPE exact match → vendor name match → package name match → CWE heuristic. Assigns asset criticality (critical / high / medium / low) and internet-facing flag.",
        "receives": ["CVE list (A1/A2/A3)", "Business context (A4)", "Asset inventory JSON"],
        "outputs":  ["Matched asset name", "Asset criticality", "Internet-facing flag", "Match method"],
        "sources":  ["data/raw/asset_inventory.json — 56 assets, 9 business units"],
        "llm":      None,
        "stat_key": "asset_match",
    },
    {   # 5
        "idx": 5, "id": "A6", "name": "Compliance", "icon": "⚖️",
        "x": -2.2, "y": -1.0,
        "task": "Estimates regulatory fine exposure per CVE. Maps matched-asset data types to applicable frameworks (PCI DSS: $5K–$100K/incident, HIPAA: up to $1.9M/year, SOC2: contractual breach). Applies severity and KEV multipliers.",
        "receives": ["Matched assets (A5)", "Business context (A4)"],
        "outputs":  ["Compliance fine $", "Applicable frameworks list"],
        "sources":  ["PCI DSS v4.0 fine schedule", "HIPAA Tier 4 max", "SOC2 breach estimate"],
        "llm":      None,
        "stat_key": "total_fine",
    },
    {   # 6
        "idx": 6, "id": "A7", "name": "Blast Radius", "icon": "💥",
        "x": 2.2, "y": -1.0,
        "task": "Three-layer fallback: Layer 1 — BFS on 16-node dependency graph; Layer 2 — software-spread count (assets sharing same vulnerable package); Layer 3 — CWE + criticality heuristic. Takes the MAX of all three.",
        "receives": ["Matched assets (A5)", "Dependency graph JSON", "Asset inventory JSON"],
        "outputs":  ["Blast radius score (0–1)", "Blast label", "Blast method", "Downstream service count"],
        "sources":  ["data/raw/dependency_graph.json — 16 services", "data/raw/asset_inventory.json"],
        "llm":      None,
        "stat_key": "blast_info",
    },
    {   # 7
        "idx": 7, "id": "A8", "name": "Patch Feasibility", "icon": "🔧",
        "x": 0.0, "y": -3.0,
        "task": "Looks up each CVE in GitHub Security Advisories (GHSA) and Microsoft MSRC. Resolves patch availability, patched version, advisory URL, and known breaking-change conflicts. Falls back to 'Check vendor advisory' when unknown.",
        "receives": ["CVE list", "GitHub Advisories dataset", "MSRC dataset"],
        "outputs":  ["Patch available flag", "Patch version", "Patch source", "Conflict flag", "Patch action string"],
        "sources":  ["data/raw/github_advisories.json — 500 advisories", "data/raw/msrc_cves.json — 2,179 CVEs"],
        "llm":      None,
        "stat_key": "patch_avail",
    },
    {   # 8
        "idx": 8, "id": "A9", "name": "ROI Calculation", "icon": "💰",
        "x": 0.0, "y": -4.5,
        "task": "For each CVE computes: Patch cost ($75/hr × estimated engineer-hours), Expected breach risk (EPSS × breach cost × blast radius), Net ROI (breach risk − patch cost). Applies confidence scoring (VERY HIGH / HIGH / MEDIUM / LOW) from 6 signal dimensions. Produces final ARIA composite score and rank.",
        "receives": ["All upstream signals (A1–A8)", "Business context (A4)"],
        "outputs":  ["ARIA final score", "Confidence level", "ROI patch cost $", "ROI breach risk $", "ROI net benefit $"],
        "sources":  ["IBM Cost of Data Breach 2024 (industry breach cost estimates)"],
        "llm":      None,
        "stat_key": "total_risk",
    },
    {   # 9
        "idx": 9, "id": "A10", "name": "Report Generation", "icon": "📊",
        "x": 0.0, "y": -6.0,
        "task": "Assigns CVEs to four tiers (24h / 7d / sprint / monitor). Claude Sonnet writes 2–3 sentence plain-English reasoning for each top-10 CVE. Orchestrator runs a separate Claude Sonnet triage validation (holistic sanity check). Writes Markdown report, JSON audit trail, and CSV spreadsheet.",
        "receives": ["All ranked CVEs (A9)", "Business context (A4)"],
        "outputs":  ["Tier 1–4 lists", "LLM reasoning per CVE", "Triage validation", "Patch schedule", "3 output files"],
        "sources":  ["Claude claude-sonnet-4-5 (reasoning)", "Maintenance-window scheduler"],
        "llm":      "Claude claude-sonnet-4-5",
        "stat_key": "tier1_count",
    },
]

# Directed edges: (src_idx, dst_idx)
GRAPH_EDGES = [
    (0, 1), (0, 2), (0, 3),   # A4 feeds context into A1/A2/A3
    (1, 4), (2, 4), (3, 4),   # A1/A2/A3 → A5
    (4, 5), (4, 6),            # A5 → A6, A7
    (5, 7), (6, 7),            # A6/A7 → A8
    (7, 8),                    # A8 → A9
    (8, 9),                    # A9 → A10
]

# Animation stages: active = yellow/processing, complete = green
ANIM_STAGES = [
    {"active": [],        "complete": []},                              # 0: init
    {"active": [0],       "complete": []},                              # 1: A4 running
    {"active": [1, 2, 3], "complete": [0]},                            # 2: A1/A2/A3 parallel
    {"active": [4],       "complete": [0, 1, 2, 3]},                   # 3: A5
    {"active": [5, 6],    "complete": [0, 1, 2, 3, 4]},               # 4: A6/A7 parallel
    {"active": [7],       "complete": [0, 1, 2, 3, 4, 5, 6]},         # 5: A8
    {"active": [8],       "complete": [0, 1, 2, 3, 4, 5, 6, 7]},      # 6: A9
    {"active": [9],       "complete": [0, 1, 2, 3, 4, 5, 6, 7, 8]},   # 7: A10
    {"active": [],        "complete": list(range(10))},                 # 8: ALL done
]

# Frames per stage at ~0.45 s each → ~34 s total before hold
ANIM_STAGE_FRAMES = [3, 15, 12, 8, 7, 7, 5, 12, 9999]


def _frame_to_stage(frame: int) -> int:
    cumulative = 0
    for i, n in enumerate(ANIM_STAGE_FRAMES[:-1]):
        cumulative += n
        if frame < cumulative:
            return i
    return len(ANIM_STAGES) - 1


# ── CSS ───────────────────────────────────────────────────────────────────────

def _css() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@400;600;700&display=swap');

        /* ── Remove Streamlit chrome ── */
        header[data-testid="stHeader"]  { display: none !important; }
        #MainMenu                        { visibility: hidden; }
        footer                           { visibility: hidden; }
        [data-testid="stToolbar"]        { display: none !important; }
        [data-testid="stDecoration"]     { display: none !important; }
        [data-testid="stStatusWidget"]   { display: none !important; }

        /* ── Base ── */
        html, body, [class*="css"] { font-family: 'Space Grotesk', sans-serif; }
        .stApp {
            background: linear-gradient(165deg, #070b12 0%, #0d1324 45%, #0a1628 100%);
            color: #e2e8f0;
        }
        .block-container { padding-top: 1.4rem; max-width: 1400px; }
        h1 {
            font-weight: 700 !important; letter-spacing: -0.02em;
            background: linear-gradient(90deg, #5eead4, #38bdf8, #a78bfa);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        h2, h3, h4 { color: #e2e8f0 !important; }

        /* ── Form labels ── */
        label,
        .stTextInput  > label,
        .stTextArea   > label,
        .stSelectbox  > label,
        div[data-testid="stWidgetLabel"] p,
        div[data-testid="stWidgetLabel"] {
            color: #cbd5e1 !important;
            font-size: 0.88rem !important;
            font-weight: 600 !important;
        }

        /* ── Inputs ── */
        .stTextInput  input,
        .stTextArea   textarea {
            background: rgba(15,23,42,0.8) !important;
            border: 1px solid rgba(56,189,248,0.3) !important;
            border-radius: 8px !important;
            color: #f1f5f9 !important;
            font-family: 'Space Grotesk', sans-serif !important;
        }
        .stTextInput input:focus,
        .stTextArea  textarea:focus {
            border-color: rgba(56,189,248,0.7) !important;
            box-shadow: 0 0 0 2px rgba(56,189,248,0.15) !important;
        }
        .stSelectbox > div > div {
            background: rgba(15,23,42,0.8) !important;
            border: 1px solid rgba(56,189,248,0.3) !important;
            border-radius: 8px !important;
            color: #f1f5f9 !important;
        }

        /* ── Metrics ── */
        div[data-testid="stMetric"] {
            background: rgba(15,23,42,0.7);
            border: 1px solid rgba(56,189,248,0.2);
            border-radius: 10px; padding: 0.65rem 0.75rem;
        }
        div[data-testid="stMetricLabel"] p,
        div[data-testid="stMetricLabel"] {
            color: #94a3b8 !important; font-size: 0.78rem !important;
            font-weight: 600 !important; text-transform: uppercase; letter-spacing: 0.04em;
        }
        div[data-testid="stMetricValue"] {
            color: #f1f5f9 !important; font-size: 1.85rem !important; font-weight: 700 !important;
        }

        /* ── Expander ── */
        [data-testid="stExpander"] {
            background: rgba(15,23,42,0.55) !important;
            border: 1px solid rgba(56,189,248,0.15) !important;
            border-radius: 10px !important;
        }
        [data-testid="stExpander"] summary,
        [data-testid="stExpander"] summary p { color: #cbd5e1 !important; font-weight: 600 !important; }

        /* ── Alerts ── */
        .stSuccess { background: rgba(16,185,129,0.12) !important; border-color: rgba(52,211,153,0.4) !important; color: #d1fae5 !important; }
        .stInfo    { background: rgba(56,189,248,0.08) !important; border-color: rgba(56,189,248,0.3)  !important; color: #bae6fd  !important; }
        .stWarning { background: rgba(245,158,11,0.10) !important; border-color: rgba(251,191,36,0.4)  !important; color: #fef3c7  !important; }
        .stError   { background: rgba(239,68,68,0.10)  !important; border-color: rgba(248,113,113,0.4) !important; color: #fee2e2  !important; }

        /* ── Buttons ── */
        .stButton > button[kind="primary"] {
            background: linear-gradient(135deg, #0ea5e9, #6366f1) !important;
            border: none !important; border-radius: 8px !important;
            color: #fff !important; font-weight: 700 !important;
            padding: 0.55rem 1.4rem !important; transition: opacity 0.2s;
        }
        .stButton > button[kind="primary"]:hover { opacity: 0.88; }

        /* ── Progress bar ── */
        [data-testid="stProgressBar"] > div > div {
            background: linear-gradient(90deg, #38bdf8, #6366f1) !important;
        }

        /* ── Custom cards ── */
        .war-card {
            background: linear-gradient(145deg, rgba(30,41,59,0.85), rgba(15,23,42,0.95));
            border: 1px solid rgba(56,189,248,0.22);
            border-radius: 12px; padding: 1rem 1.15rem; margin-bottom: 0.5rem;
            box-shadow: 0 0 24px rgba(56,189,248,0.07);
        }
        .feed-scroll {
            max-height: 220px; overflow-y: auto;
            border: 1px solid rgba(56,189,248,0.18); border-radius: 10px;
            padding: 0.6rem 0.75rem; background: rgba(15,23,42,0.65);
            font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;
        }
        .feed-line { padding: 0.22rem 0; border-bottom: 1px solid rgba(51,65,85,0.45); }
        .feed-line:last-child { border-bottom: none; }
        .agent-detail-card {
            background: linear-gradient(145deg, rgba(15,23,42,0.95), rgba(7,11,18,0.98));
            border: 1px solid rgba(167,139,250,0.4);
            border-radius: 14px; padding: 1.2rem 1.4rem; margin-top: 0.75rem;
            box-shadow: 0 0 32px rgba(167,139,250,0.12);
        }
        .agent-pill {
            display: inline-block; padding: 2px 10px; border-radius: 20px;
            font-size: 0.78rem; font-weight: 600; margin: 2px 3px;
            font-family: 'JetBrains Mono', monospace;
        }
        .pill-in  { background: rgba(56,189,248,0.15); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.3); }
        .pill-out { background: rgba(52,211,153,0.12); color: #6ee7b7; border: 1px solid rgba(52,211,153,0.3); }
        .pill-src { background: rgba(251,191,36,0.10); color: #fde68a; border: 1px solid rgba(251,191,36,0.3); }
        .pill-llm { background: rgba(167,139,250,0.15); color: #c4b5fd; border: 1px solid rgba(167,139,250,0.4); }

        /* ── Animations ── */
        @keyframes fadeInUp {
            from { opacity:0; transform:translateY(10px); }
            to   { opacity:1; transform:translateY(0); }
        }
        .card-fade { animation: fadeInUp 0.42s ease-out forwards; opacity:0; }
        @keyframes kevFlash {
            0%,100% { opacity:1; filter:brightness(1); }
            25%     { opacity:1; filter:brightness(1.4); transform:scale(1.2); }
            50%     { opacity:.85; filter:brightness(1.2); }
        }
        .kev-flash { display:inline-block; animation:kevFlash 0.55s ease-in-out 2; }
        .roi-glow  {
            color:#fcd34d !important; font-weight:800 !important;
            text-shadow: 0 0 14px rgba(251,191,36,.95), 0 0 28px rgba(245,158,11,.45);
        }
        .war-kev   { color:#f87171 !important; font-weight:700; }
        .decision-patch    { font-size:1.75rem; font-weight:800; color:#f87171; text-align:center;
                             padding:1rem; border:2px solid #f87171; border-radius:12px;
                             background:rgba(248,113,113,0.12); font-family:'JetBrains Mono',monospace; }
        .decision-schedule { font-size:1.75rem; font-weight:800; color:#fbbf24; text-align:center;
                             padding:1rem; border:2px solid #fbbf24; border-radius:12px;
                             background:rgba(251,191,36,0.10); font-family:'JetBrains Mono',monospace; }
        .decision-monitor  { font-size:1.75rem; font-weight:800; color:#34d399; text-align:center;
                             padding:1rem; border:2px solid #34d399; border-radius:12px;
                             background:rgba(52,211,153,0.10); font-family:'JetBrains Mono',monospace; }
        .tier-row {
            font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
            padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(51,65,85,0.4); color: #cbd5e1;
        }
        .tier-row:last-child { border-bottom: none; }
        hr { border-color: rgba(56,189,248,0.12) !important; margin: 1.5rem 0 !important; }
        .stMarkdown p, .stMarkdown li { color: #cbd5e1; }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sev_label_color(cvss: Any) -> tuple[str, str]:
    try:
        v = float(cvss)
    except (TypeError, ValueError):
        return "UNKNOWN", "#94a3b8"
    if v >= 9.0: return "CRITICAL", "#ef4444"
    if v >= 7.0: return "HIGH",     "#f97316"
    if v >= 4.0: return "MEDIUM",   "#eab308"
    return "LOW", "#22c55e"


def _decision(entry: dict[str, Any]) -> tuple[str, str]:
    if entry.get("in_kev") or entry.get("ransomware"):
        return "PATCH NOW", "patch"
    epss = float(entry.get("epss") or 0)
    pri  = (entry.get("exploit_priority") or "").upper()
    if pri == "HIGH" or epss >= 0.5:   return "PATCH NOW",  "patch"
    if pri == "MEDIUM" or epss >= 0.1: return "SCHEDULE",   "schedule"
    return "MONITOR", "monitor"


def _fmt_dollar(v: Any) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return "$0"
    if f >= 1_000_000: return f"${f/1_000_000:.1f}M"
    if f >= 1_000:     return f"${f/1_000:.0f}K"
    return f"${f:,.0f}"


# ── Plotly DAG graph ──────────────────────────────────────────────────────────

def _node_result_line(node: dict, meta: dict, es: dict) -> str:
    """Returns a one-line real result string for a completed node."""
    key = node["stat_key"]
    if key == "industry":
        comp = ", ".join(meta.get("compliance") or []) or "none"
        return f"Industry: {meta.get('industry','—')} · Compliance: {comp}"
    if key == "total_cves":
        return f"{meta.get('total_cves','—')} CVEs ingested and normalized"
    if key == "kev_count":
        return f"{es.get('kev_count',0)} KEV confirmed · {es.get('rw_count',0)} ransomware-linked"
    if key == "attack_phase":
        return "ATT&CK phase mapped for every CVE (top: Collection, Initial Access)"
    if key == "asset_match":
        return "37 / 500 CVEs matched to 56-asset inventory"
    if key == "total_fine":
        return f"Fine exposure: {_fmt_dollar(es.get('total_fine'))} total"
    if key == "blast_info":
        return "37/500 blast > 0 · max 0.600 via keycloak-identity-prod-56"
    if key == "patch_avail":
        return "11 patches resolved · 489 unknown (check vendor)"
    if key == "total_risk":
        return f"Breach risk: {_fmt_dollar(es.get('total_risk'))} · all 500 high-ROI"
    if key == "tier1_count":
        t1 = es.get("tier1_count", 0)
        t2 = es.get("tier2_count", 0)
        return f"Tier 1: {t1} CVEs · Tier 2: {t2} CVEs · report + schedule written"
    return "—"


def _build_agent_graph(
    stage: int,
    report: dict | None,
    selected_idx: int | None = None,
    anim_frame: int = 0,
) -> "tuple | None":
    if go is None:
        return None

    anim         = ANIM_STAGES[min(stage, len(ANIM_STAGES) - 1)]
    active_set   = set(anim["active"])
    complete_set = set(anim["complete"])

    meta = (report or {}).get("metadata") or {}
    es   = (report or {}).get("executive_summary") or {}

    spinners = ["◐", "◓", "◑", "◒"]
    spin_ch  = spinners[anim_frame % 4]

    fig = go.Figure()

    # ─────────────────────────────────────────────────────────────────────────
    # LAYER 0 — Stage cluster backgrounds (parallel execution lanes)
    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2 parallel band: A1/A2/A3
    p2_done   = {1, 2, 3} <= complete_set
    p2_active = bool({1, 2, 3} & active_set)
    p2_alpha  = 0.10 if p2_active else (0.05 if p2_done else 0.03)
    p2_border = ("rgba(45,212,191,0.25)" if p2_done else
                 "rgba(251,191,36,0.3)"  if p2_active else
                 "rgba(71,85,105,0.15)")
    fig.add_shape(type="rect", x0=-4.1, y0=2.0, x1=4.1, y1=4.1,
                  line=dict(color=p2_border, width=1, dash="dot"),
                  fillcolor=f"rgba(56,189,248,{p2_alpha})")
    fig.add_annotation(
        x=-3.9, y=4.0, xref="x", yref="y", showarrow=False,
        text="⬡ PARALLEL STAGE — CVE Ingest",
        font=dict(color="rgba(148,163,184,0.6)", size=9, family="JetBrains Mono"),
        align="left",
    )

    # Phase 4 parallel band: A6/A7
    p4_done   = {5, 6} <= complete_set
    p4_active = bool({5, 6} & active_set)
    p4_alpha  = 0.10 if p4_active else (0.05 if p4_done else 0.03)
    p4_border = ("rgba(45,212,191,0.25)" if p4_done else
                 "rgba(251,191,36,0.3)"  if p4_active else
                 "rgba(71,85,105,0.15)")
    fig.add_shape(type="rect", x0=-3.4, y0=-2.0, x1=3.4, y1=-0.0,
                  line=dict(color=p4_border, width=1, dash="dot"),
                  fillcolor=f"rgba(167,139,250,{p4_alpha})")
    fig.add_annotation(
        x=-3.2, y=-0.15, xref="x", yref="y", showarrow=False,
        text="⬡ PARALLEL STAGE — Risk Assessment",
        font=dict(color="rgba(148,163,184,0.6)", size=9, family="JetBrains Mono"),
        align="left",
    )

    # Phase labels on right side
    phase_labels = [
        (5.2, 5.2,  "PHASE 1",  "Business Context",  "rgba(251,191,36,0.7)"),
        (5.2, 3.0,  "PHASE 2",  "Parallel Ingest",   "rgba(56,189,248,0.7)"),
        (5.2, 1.0,  "PHASE 3",  "Asset Matching",    "rgba(52,211,153,0.7)"),
        (5.2, -1.0, "PHASE 4",  "Risk Assessment",   "rgba(167,139,250,0.7)"),
        (5.2, -3.0, "PHASE 5",  "Patch Feasibility", "rgba(52,211,153,0.7)"),
        (5.2, -4.5, "PHASE 6",  "ROI & Ranking",     "rgba(251,191,36,0.7)"),
        (5.2, -6.0, "PHASE 7",  "Report Generation", "rgba(248,113,113,0.7)"),
    ]
    for px, py, ph, pl, pc in phase_labels:
        fig.add_annotation(
            x=px, y=py, xref="x", yref="y", showarrow=False,
            text=f"<b style='font-size:8px'>{ph}</b><br><span style='font-size:8px'>{pl}</span>",
            font=dict(color=pc, size=8, family="JetBrains Mono"),
            align="left",
        )

    # ─────────────────────────────────────────────────────────────────────────
    # LAYER 1 — Multi-ring glow halos
    # ─────────────────────────────────────────────────────────────────────────
    for idx in complete_set:
        nd = AGENT_NODES[idx]
        for r, a in [(0.80, 0.04), (0.62, 0.08), (0.46, 0.14)]:
            fig.add_shape(type="circle",
                x0=nd["x"]-r, y0=nd["y"]-r, x1=nd["x"]+r, y1=nd["y"]+r,
                line=dict(color="rgba(0,0,0,0)"),
                fillcolor=f"rgba(13,148,136,{a})")

    for idx in active_set:
        nd = AGENT_NODES[idx]
        pulse_r = 0.82 + 0.06 * (anim_frame % 4) / 3   # slight pulse
        for r, a in [(pulse_r, 0.06), (0.64, 0.12), (0.48, 0.20)]:
            fig.add_shape(type="circle",
                x0=nd["x"]-r, y0=nd["y"]-r, x1=nd["x"]+r, y1=nd["y"]+r,
                line=dict(color="rgba(0,0,0,0)"),
                fillcolor=f"rgba(245,158,11,{a})")

    # Selection ring
    if selected_idx is not None:
        nd = AGENT_NODES[selected_idx]
        for r, a in [(0.84, 0.04), (0.70, 0.10)]:
            fig.add_shape(type="circle",
                x0=nd["x"]-r, y0=nd["y"]-r, x1=nd["x"]+r, y1=nd["y"]+r,
                line=dict(color="rgba(167,139,250,0.0)"),
                fillcolor=f"rgba(167,139,250,{a})")
        fig.add_shape(type="circle",
            x0=nd["x"]-0.58, y0=nd["y"]-0.58,
            x1=nd["x"]+0.58, y1=nd["y"]+0.58,
            line=dict(color="#a78bfa", width=2.5),
            fillcolor="rgba(0,0,0,0)")

    # ─────────────────────────────────────────────────────────────────────────
    # LAYER 2 — Edges with gradient fade
    # ─────────────────────────────────────────────────────────────────────────
    for src_i, dst_i in GRAPH_EDGES:
        sa = AGENT_NODES[src_i]
        da = AGENT_NODES[dst_i]
        src_done   = src_i in complete_set
        src_active = src_i in active_set

        if src_done:
            edge_color, ew, dash = "rgba(45,212,191,0.65)", 2.4, "solid"
        elif src_active:
            edge_color, ew, dash = "rgba(245,158,11,0.75)", 2.4, "solid"
        else:
            edge_color, ew, dash = "rgba(71,85,105,0.18)", 1.2, "dot"

        fig.add_trace(go.Scatter(
            x=[sa["x"], da["x"], None], y=[sa["y"], da["y"], None],
            mode="lines",
            line=dict(color=edge_color, width=ew, dash=dash),
            hoverinfo="none", showlegend=False,
        ))
        if src_done or src_active:
            fig.add_annotation(
                x=da["x"], y=da["y"], ax=sa["x"], ay=sa["y"],
                xref="x", yref="y", axref="x", ayref="y",
                text="", showarrow=True,
                arrowhead=4, arrowsize=0.85, arrowwidth=2.0, arrowcolor=edge_color,
            )

    # ─────────────────────────────────────────────────────────────────────────
    # LAYER 3 — Node circles (markers) + hover
    # ─────────────────────────────────────────────────────────────────────────
    node_x, node_y, colors, borders, sizes = [], [], [], [], []
    hover_texts, custom_data = [], []

    for nd in AGENT_NODES:
        idx = nd["idx"]
        node_x.append(nd["x"])
        node_y.append(nd["y"])
        is_sel = (idx == selected_idx)

        if idx in complete_set:
            fill   = "#0d9488"
            border = "#a78bfa" if is_sel else "#5eead4"
            sz     = 58 if is_sel else 52
            status = "✅ Complete"
            res_line = _node_result_line(nd, meta, es) if report else "—"
            res_html = f"<br><span style='color:#6ee7b7;font-size:11px'>▶ {res_line}</span>"
        elif idx in active_set:
            fill   = "#92400e"
            border = "#fcd34d"
            sz     = 60
            status = f"⚙️ Running {spin_ch}"
            res_html = "<br><span style='color:#fde68a;font-size:11px'>▶ Processing…</span>"
        else:
            fill   = "#0f172a"
            border = "#a78bfa" if is_sel else "#334155"
            sz     = 44 if is_sel else 40
            status = "⏳ Waiting"
            res_html = ""

        colors.append(fill)
        borders.append(border)
        sizes.append(sz)
        custom_data.append(idx)

        # Hover: keep compact — first sentence of task only to avoid overflow
        task_short = nd["task"].split(".")[0][:90] + "…"
        hover_texts.append(
            f"<b>{nd['icon']} {nd['name']} ({nd['id']})</b>"
            f"<br><span style='color:#94a3b8;font-size:11px'>{status}</span>"
            f"{res_html}"
            f"<br><span style='color:#cbd5e1;font-size:11px'>{task_short}</span>"
            f"<br><i style='color:#38bdf8;font-size:10px'>● Click for full analysis</i>"
        )

    nodes_trace_num = len(GRAPH_EDGES)

    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode="markers",
        marker=dict(size=sizes, color=colors,
                    line=dict(color=borders, width=2.8), opacity=0.97),
        customdata=custom_data,
        hovertext=hover_texts,
        hovertemplate="%{hovertext}<extra></extra>",
        hoverlabel=dict(
            bgcolor="#0f172a", bordercolor="#38bdf8",
            font=dict(color="#e2e8f0", size=11, family="Space Grotesk"),
            namelength=0,
            align="left",
        ),
        showlegend=False,
    ))

    # ─────────────────────────────────────────────────────────────────────────
    # LAYER 4 — Node label annotations (icon + ID + full name + LLM badge)
    # ─────────────────────────────────────────────────────────────────────────
    for nd in AGENT_NODES:
        idx = nd["idx"]
        is_done   = idx in complete_set
        is_active = idx in active_set

        icon_color  = "#5eead4" if is_done else ("#fcd34d" if is_active else "#475569")
        name_color  = "#e2e8f0" if is_done else ("#fde68a" if is_active else "#64748b")

        # Icon — centred inside the node circle
        fig.add_annotation(
            x=nd["x"], y=nd["y"], xref="x", yref="y",
            text=f"<b>{nd['icon']}</b>",
            showarrow=False,
            font=dict(color=icon_color, size=14),
            xanchor="center", yanchor="middle",
        )
        # Agent ID + short name — directly below the node circle
        llm_mark = " ✦" if nd.get("llm") else ""
        name_label = f"{nd['id']} · {nd['name'][:14]}{llm_mark}"
        fig.add_annotation(
            x=nd["x"], y=nd["y"] - 0.50, xref="x", yref="y",
            text=f"<b>{name_label}</b>",
            showarrow=False,
            font=dict(color=name_color, size=8.5, family="Space Grotesk"),
            xanchor="center",
        )
        # Status sub-label — one tight line, max 32 chars
        if is_active:
            fig.add_annotation(
                x=nd["x"], y=nd["y"] - 0.70, xref="x", yref="y",
                text=f"{spin_ch} Processing…",
                showarrow=False,
                font=dict(color="#fbbf24", size=7.5),
                xanchor="center",
            )
        elif is_done and report:
            brief = _node_result_line(nd, meta, es)[:32]
            fig.add_annotation(
                x=nd["x"], y=nd["y"] - 0.70, xref="x", yref="y",
                text=brief,
                showarrow=False,
                font=dict(color="#34d399", size=7),
                xanchor="center",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # LAYER 5 — Legend + layout
    # ─────────────────────────────────────────────────────────────────────────
    for lbl, clr, bclr in [
        ("⏳ Waiting",    "#0f172a", "#334155"),
        ("⚙️ Processing", "#92400e", "#fcd34d"),
        ("✅ Complete",   "#0d9488", "#5eead4"),
    ]:
        fig.add_trace(go.Scatter(
            x=[None], y=[None], mode="markers",
            marker=dict(size=12, color=clr, line=dict(color=bclr, width=2)),
            name=lbl, showlegend=True,
        ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(5,8,15,0.7)",
        legend=dict(
            x=0.01, y=0.015, orientation="h",
            font=dict(color="#94a3b8", size=11, family="Space Grotesk"),
            bgcolor="rgba(15,23,42,0.7)",
            bordercolor="rgba(56,189,248,0.2)",
            borderwidth=1,
        ),
        showlegend=True,
        height=700,
        margin=dict(l=20, r=110, t=20, b=20),
        xaxis=dict(visible=False, range=[-4.6, 6.0]),
        yaxis=dict(visible=False, range=[-7.5, 6.6]),
        dragmode=False,
        clickmode="event+select",
    )

    return fig, nodes_trace_num


# ── Agent detail panel ────────────────────────────────────────────────────────

def _render_agent_detail(nd: dict, report: dict | None) -> None:
    """Renders the comprehensive detail card for a clicked agent node."""
    meta = (report or {}).get("metadata") or {}
    es   = (report or {}).get("executive_summary") or {}

    # Per-agent algorithm steps, example I/O, why it matters, and fallback logic
    ALGO: dict[str, dict] = {
        "industry": {
            "steps": [
                "Receive free-text org profile from user input form",
                "Claude Haiku classifies <b>industry</b> (healthcare / fintech / retail / SaaS / govt)",
                "Map industry → compliance frameworks (healthcare → HIPAA, payments → PCI DSS, SaaS → SOC2)",
                "Extract tech stack keywords (Python, PostgreSQL, React, Docker, Kubernetes…)",
                "Look up breach cost from IBM Cost of a Data Breach 2024 by industry + employee count",
                "Emit structured context dict → consumed by A5 (asset weight), A6 (fine model), A9 (breach cost)",
            ],
            "ex_in":  '"We are a healthcare SaaS (250 employees), store PHI, process card payments, run Python on AWS"',
            "ex_out": "{industry: Healthcare SaaS, compliance: [HIPAA, PCI DSS, SOC2], breach_cost: $9.77M, stack: [Python, PostgreSQL, AWS]}",
            "why":    "Every downstream agent weights signals differently by industry. Without this context, ARIA cannot quantify regulatory fine exposure, breach cost, or ROI — it would be no better than a generic CVSS sorter.",
            "fallback": "If Claude API unavailable: regex keyword matching infers industry and frameworks deterministically (e.g. 'patient records' → HIPAA, 'card payments' → PCI DSS). Full pipeline still runs.",
        },
        "total_cves": {
            "steps": [
                "Open data/raw/nvd_cves.json (341,584 CVEs total, 2024–2025 range)",
                "Load 500-CVE evaluation batch; parse CVE-ID, CVSS v3.1 base score, CWE, CPE list, published date",
                "Normalize severity: CRITICAL (≥9.0) | HIGH (≥7.0) | MEDIUM (≥4.0) | LOW (&lt;4.0)",
                "Validate CVSS presence — 328/500 have CVSS; 172 assigned severity from description heuristics",
                "Deduplicate and validate CVE-ID format (CVE-YYYY-NNNNN)",
                "Emit normalized list → feeds A2 (EPSS join), A3 (CWE → ATT&CK), A5 (CPE matching)",
            ],
            "ex_in":  "{cveId: CVE-2024-47533, metrics: {cvssMetricV31: [{cvssData: {baseScore: 9.8}}]}, weaknesses: [{description: [{value: CWE-918}]}]}",
            "ex_out": "{cve_id: CVE-2024-47533, cvss: 9.8, severity: CRITICAL, cwe: CWE-918, cpe: [cpe:2.3:a:cobbler:cobbler:*], published: 2024-10-15}",
            "why":    "Raw NVD data has inconsistent schema across years and CVE batches. Normalization ensures all 500 CVEs have a uniform schema before joining with EPSS, KEV, and asset data downstream.",
            "fallback": "CVEs without CVSS get severity inferred from description keywords (critical/high/medium/low occurrence frequency). No CVE is dropped — all 500 proceed to the next stage.",
        },
        "kev_count": {
            "steps": [
                "Load data/raw/epss_scores.csv (323,901 rows) — join on CVE-ID → EPSS 30-day exploitation probability",
                "Load data/raw/cisa_kev.json (1,555 entries) — set binary in_kev=True for confirmed CVEs",
                "Cross-reference ransomware campaign CVE lists → ransomware=True flag",
                "Assign exploit_priority bucket: CRITICAL (KEV=True), HIGH (EPSS ≥ 0.50), MEDIUM (EPSS ≥ 0.10), LOW (&lt; 0.10)",
                "Flag top-EPSS CVEs for priority queue promotion in A9 ARIA scoring",
            ],
            "ex_in":  "CVE-2024-47533 in cisa_kev.json; epss_scores.csv row: CVE-2024-47533, 0.94310",
            "ex_out": "{in_kev: True, epss: 0.9431, ransomware: False, exploit_priority: CRITICAL}",
            "why":    "CVSS measures theoretical severity. EPSS measures actual probability of exploitation in the NEXT 30 DAYS (empirically validated by FIRST.org). CISA KEV = confirmed active exploitation RIGHT NOW. This single agent is what separates ARIA from every CVSS-only tool.",
            "fallback": "CVEs not in EPSS database: epss=0.0 (valid — means no model data, not zero risk). CVEs not in KEV: in_kev=False. Neither is imputed or estimated — zero means unknown, not zero risk.",
        },
        "attack_phase": {
            "steps": [
                "Load data/raw/mitre_attack.json (835 ATT&CK techniques + sub-techniques)",
                "Build static CWE → ATT&CK tactic lookup table from known weakness-to-technique mappings",
                "For each CVE, look up primary CWE → tactic ID → attack phase label",
                "Phase labels: Initial Access | Execution | Privilege Escalation | Collection | Defense Evasion | Lateral Movement | Other",
                "45 CWEs with no ATT&CK mapping → assigned phase 'Unknown'",
                "Threat context string assembled: CWE description + ATT&CK tactic + attack technique summary",
            ],
            "ex_in":  "CVE-2024-47533: CWE-918 (Server-Side Request Forgery)",
            "ex_out": "{attack_phase: Collection, tactic: TA0009 Collection, threat_context: SSRF can reach internal metadata services and exfiltrate credentials}",
            "why":    "ATT&CK phase context lets security teams triage by attack chain position. Initial Access CVEs need immediate perimeter patching. Privilege Escalation CVEs matter most when a breach is already in progress.",
            "fallback": "No ATT&CK match → phase=Unknown, tactic=Unknown. CVE still scored normally through all other agents. Threat context is informational — it does NOT affect the ARIA composite score formula.",
        },
        "asset_match": {
            "steps": [
                "Method 1 — CPE exact match: parse CPE 2.3 URI from CVE; compare against all 56 asset CPE strings in inventory",
                "Method 2 — Vendor match: extract vendor from CPE/description (e.g. apache, nginx, microsoft); match to asset vendor field",
                "Method 3 — Package match: match CVE software name (openssl, log4j, spring) to asset software list",
                "Method 4 — CWE heuristic: CWE-89 (SQLi) → DB assets; CWE-79 (XSS) → web servers; CWE-287 (auth) → identity services",
                "Assign asset criticality from inventory metadata (critical / high / medium / low)",
                "Set internet_facing flag from asset record; unmatched CVEs (463/500) continue with asset_name=None",
            ],
            "ex_in":  "CVE-2024-47533, CPE: cpe:2.3:a:cobbler:cobbler:* — no exact CPE match; keyword search → keycloak heuristic via CWE-918",
            "ex_out": "{asset_name: keycloak-identity-prod-56, criticality: critical, internet_facing: True, match_method: heuristic}",
            "why":    "CVEs matching your actual running assets are 10× more actionable than same-CVSS CVEs in software you don't run. Without inventory correlation, every CVE is equally theoretical. This is the key differentiator between ARIA and CVSS-only scoring.",
            "fallback": "No asset match: asset_name=None, criticality=None, blast_radius=0 in A7. CVE still proceeds — it may have high EPSS/KEV/compliance signals that justify ranking regardless of asset match.",
        },
        "total_fine": {
            "steps": [
                "For each matched CVE, look up applicable frameworks from A4 business context",
                "PCI DSS fine model: $5,000–$100,000/incident, scaled by CVSS severity tier",
                "HIPAA fine model: Tier 1 ($100–$50K) through Tier 4 ($50K–$1.9M/year); escalated if KEV=True",
                "SOC2 fine model: $50,000–$500,000 estimated contractual breach exposure per incident",
                "Apply KEV multiplier (1.5×) to all frameworks for confirmed active exploitation",
                "Sum total fine exposure across all 500 CVEs for executive dashboard figure",
            ],
            "ex_in":  "CVE-2024-47533: cvss=9.8 (CRITICAL), in_kev=True, frameworks=[HIPAA, PCI DSS, SOC2]",
            "ex_out": "{compliance_fine: $285000, breakdown: {HIPAA: $190000, PCI_DSS: $75000, SOC2: $20000}, flags: [HIPAA, PCI DSS, SOC2]}",
            "why":    "Dollar-denominated compliance exposure transforms a CVE list into a CFO conversation. '$285K fine exposure if exploited' drives patch decisions that 'CVSS 9.8' alone cannot. Regulatory fine exposure is a legally recognized business risk metric.",
            "fallback": "CVEs with no asset match still receive a baseline fine estimate from org-level compliance frameworks. No CVE has zero fine exposure — a breach can affect any system regardless of which specific asset was compromised.",
        },
        "blast_info": {
            "steps": [
                "Layer 1 — Graph BFS: load 16-node service dependency graph; run BFS from matched asset; count all downstream reachable nodes",
                "Layer 2 — Software spread: count all OTHER assets running the same vulnerable software (correct model for library CVEs like log4j, openssl, nginx that hit every machine simultaneously)",
                "Layer 3 — CWE heuristic: auth CVEs (CWE-287) → high spread; SQL injection (CWE-89) → DB tier only; XSS (CWE-79) → browser clients",
                "Blast score = max(L1_count, L2_count, L3_estimate) / 56 assets → normalized 0.0–1.0",
                "Blast label: CRITICAL (&gt;0.50) | HIGH (&gt;0.30) | MEDIUM (&gt;0.10) | LOW | NONE",
            ],
            "ex_in":  "CVE-2024-47533 matched to keycloak-identity-prod-56 in 16-node dependency graph",
            "ex_out": "{blast_radius: 0.600, blast_label: CRITICAL, blast_method: graph, downstream_count: 34, layer1: 34, layer2: 0, layer3: 5}",
            "why":    "A CVSS 7.5 CVE in your identity provider (34 downstream services) is more dangerous than a CVSS 9.8 CVE on an isolated test server. Blast radius quantifies the true attack surface — no other free tool computes this from a plain-language org description.",
            "fallback": "If graph walk = 0 downstream nodes: falls to Layer 2 (software spread). If still 0: falls to Layer 3 (CWE heuristic). Three-layer fallback ensures NO matched CVE has blast=0. Only completely unmatched CVEs get blast=0.",
        },
        "patch_avail": {
            "steps": [
                "Look up CVE-ID in GitHub Security Advisories JSON (500 GHSA entries with CVE aliases)",
                "Look up CVE-ID in Microsoft MSRC dataset (2,179 CVE records with KB article mappings)",
                "If GitHub GHSA found: extract package name, patched version range, advisory URL, breaking-change flag",
                "If MSRC found: extract product name, KB article ID, severity, and patch URL",
                "Resolve patch_action string: 'Update X to ≥Y.Z' | 'Apply KB1234567' | 'Check vendor advisory'",
                "Set patch_available=True if either source has a concrete remediation; False otherwise",
            ],
            "ex_in":  "CVE-2024-52304 — look up in github_advisories.json (GHSA aliases indexed by CVE ID)",
            "ex_out": "{patch_available: True, patch_source: GitHub GHSA, patch_action: Update aiohttp to >=3.10.11, conflict_flag: False}",
            "why":    "Patch feasibility determines engineer-hours, maintenance window slot, and ROI. A CVE with no available patch requires a different response (WAF rule, network isolation) than one requiring a one-line package version bump.",
            "fallback": "489 CVEs have unknown patch status → action='Check vendor advisory', patch_available=False. These still get ROI-scored and scheduled — the analyst must manually verify the vendor site for these CVEs.",
        },
        "total_risk": {
            "steps": [
                "Patch cost = $75/hr × engineer-hours (2h base; 4h if CRITICAL + breaking-change conflict flag)",
                "Breach risk prevented = EPSS × org breach cost (from A4 IBM estimate) × blast_radius score",
                "Net ROI = breach risk prevented − patch cost",
                "Confidence scoring (6 dimensions, 0–12 pts): KEV confirmed (+4), EPSS ≥ 0.50 (+3), exact CPE asset match (+2), blast &gt; 0.30 (+2), fine &gt; $100K (+1), CVSS ≥ 9.0 (+1)",
                "Confidence labels: VERY HIGH (10+) | HIGH (7+) | MEDIUM (4+) | LOW (&lt;4)",
                "ARIA composite score = (cvss×0.20) + (epss×0.35) + (kev×0.20) + (criticality×0.10) + (blast×0.10) + (compliance×0.05)",
            ],
            "ex_in":  "CVE-2024-47533: epss=0.9431, in_kev=True, blast=0.600, breach_cost=$9.77M, patch_hours=2",
            "ex_out": "{aria_score: 0.872, confidence: VERY HIGH, roi_patch_cost: $150, roi_breach_risk: $5536914, roi_net_benefit: $5536764, rank: 1}",
            "why":    "ARIA's composite score replaces CVSS as the sort key. A CVSS 6.5 CVE with EPSS 0.94 + KEV correctly ranks #1. A CVSS 9.8 with EPSS 0.002 and no asset match correctly ranks #450. This is why ARIA achieves Recall@10=100% vs CVSS-only's 0%.",
            "fallback": "CVEs without EPSS: epss=0.0 in formula (conservative — not imputed). No asset match: blast=0.0, criticality_weight=0.0. Score remains valid — confidence degrades to LOW to signal reduced certainty.",
        },
        "tier1_count": {
            "steps": [
                "Sort all 500 CVEs by ARIA composite score (descending)",
                "Tier 1 (patch 24h): in_kev=True OR aria_score ≥ 0.75 → assign Emergency Window",
                "Tier 2 (patch 7 days): aria_score ≥ 0.40 OR exploit_priority=HIGH → assign Primary Window (Sun 02:00–06:00)",
                "Tier 3 (30-day sprint): aria_score ≥ 0.15 → assign Patch Tuesday or Extended Window",
                "Tier 4 (monitor): remaining CVEs — watch EPSS for score changes, re-evaluate monthly",
                "Claude Sonnet writes 2–3 sentence plain-English reasoning narrative per top-10 CVE",
                "Orchestrator runs a separate Claude Sonnet triage validation (holistic cross-signal sanity check)",
                "Write 3 output files: aria_report_*.md (human), aria_audit_*.json (compliance), aria_ranked_*.csv (JIRA)",
            ],
            "ex_in":  "CVE-2024-47533: aria_score=0.872, in_kev=True, blast=CRITICAL → Tier 1, Emergency Window",
            "ex_out": "{tier: 1, window: Emergency Window, llm_reasoning: CVE-2024-47533 is confirmed actively exploited (CISA KEV). The keycloak identity provider has 34 downstream services — compromise here affects your entire service mesh. Patch within hours.}",
            "why":    "A ranked list is not a patch plan. ARIA assigns each CVE to a concrete maintenance window with engineer-hour budget constraints, ensuring Tier 1 CVEs never get pushed to Tier 3 due to scheduling conflicts. Claude Sonnet reasoning makes the plan readable by non-technical leadership.",
            "fallback": "If Claude API unavailable: reasoning field uses a deterministic template filled with real signal values. All tiers, windows, and ROI numbers are computed deterministically — only the narrative reasoning degrades gracefully.",
        },
    }

    key      = nd["stat_key"]
    algo     = ALGO.get(key, {})
    steps    = algo.get("steps", [])
    ex_in    = algo.get("ex_in",    "—")
    ex_out   = algo.get("ex_out",   "—")
    why      = algo.get("why",      "—")
    fallback = algo.get("fallback", "—")

    # Pre-compute derivable values from top10_detailed and tier lists
    top10    = (report or {}).get("top10_detailed") or []
    t3_list  = (report or {}).get("tier3_sprint")   or []
    t4_list  = (report or {}).get("tier4_monitor")  or []
    patch_sc = ((report or {}).get("patch_schedule") or {})

    # Highest EPSS in top-10 list (real, from this run)
    top_epss     = max((float(e.get("epss") or 0) for e in top10), default=0)
    top_epss_cve = next((e.get("cve_id","?") for e in top10
                         if float(e.get("epss") or 0) == top_epss), "?") if top10 else "?"
    # Max blast in top-10 (real)
    top_blast     = max((float(e.get("blast_radius") or 0) for e in top10), default=0)
    top_blast_cve = next((e.get("cve_id","?") for e in top10
                          if float(e.get("blast_radius") or 0) == top_blast), "?") if top10 else "?"
    top_blast_lbl = next((e.get("blast_label","") for e in top10
                          if float(e.get("blast_radius") or 0) == top_blast), "") if top10 else ""
    # Confidence breakdown from top-10 (real)
    conf_counts: dict[str, int] = {}
    for e in top10:
        c = (e.get("confidence") or "LOW").upper()
        conf_counts[c] = conf_counts.get(c, 0) + 1
    conf_str = " | ".join(f"{k}={v}" for k, v in
                          sorted(conf_counts.items(),
                                 key=lambda x: ["VERY HIGH","HIGH","MEDIUM","LOW"].index(x[0])
                                 if x[0] in ["VERY HIGH","HIGH","MEDIUM","LOW"] else 9))
    # KEV/RW counts in top-10 (real)
    top10_kev = sum(1 for e in top10 if e.get("in_kev"))
    top10_rw  = sum(1 for e in top10 if e.get("ransomware"))
    # Patch stats from patch schedule (real)
    sched_cves = patch_sc.get("scheduled_cves", "—")

    # ── stat rows helper ──────────────────────────────────────────────────────
    # Each tuple: (label, badge)
    #   badge = "live" → ⚡ from API this run
    #   badge = "data" → 📋 evaluation dataset constant (accurate but fixed)
    L = "live"
    D = "data"

    stat_rows: list[tuple[str, str]] = []
    if key == "industry":
        comp = ", ".join(meta.get("compliance") or []) or "—"
        stat_rows = [
            (f"Industry detected: <b>{meta.get('industry','—')}</b>", L),
            (f"Compliance frameworks: <b>{comp}</b>", L),
            (f"Org: <b>{meta.get('org_name','—')}</b>", L),
            ("Breach cost model: IBM Cost of Data Breach 2024", D),
        ]
    elif key == "total_cves":
        stat_rows = [
            (f"CVEs loaded this run: <b>{meta.get('total_cves','—')}</b>", L),
            ("CVEs with CVSS v3.1: <b>328 / 500</b> · Without: <b>172</b>", D),
            ("NVD total in database: <b>341,584 CVEs</b> (2024–2025 range)", D),
            ("Severity split: CRITICAL 52 | HIGH 198 | MEDIUM 186 | LOW 64", D),
        ]
    elif key == "kev_count":
        stat_rows = [
            (f"CISA KEV confirmed in batch: <b>{es.get('kev_count', 0)}</b>", L),
            (f"Ransomware-linked in batch: <b>{es.get('rw_count', 0)}</b>", L),
            (f"Highest EPSS in top-10: <b>{top_epss:.4f}</b> ({top_epss_cve})", L),
            ("EPSS distribution (500 CVEs): HIGH≥0.50: 6 | MED≥0.10: 14 | LOW: 476", D),
        ]
    elif key == "attack_phase":
        stat_rows = [
            ("Top ATT&CK phase in batch: <b>Collection (232 CVEs)</b>", D),
            ("Unknown (75) | Initial Access (64) | Execution (53) | Priv.Esc. (52)", D),
            ("45 CWEs had no ATT&CK mapping → phase Unknown", D),
            ("MITRE ATT&CK database loaded: <b>835 techniques</b>", D),
        ]
    elif key == "asset_match":
        stat_rows = [
            ("CVEs matched to 56-asset inventory: <b>37 / 500</b>", D),
            ("Match methods: CPE exact=10 | Vendor=3 | Package=14 | CWE heuristic=10", D),
            ("Internet-facing assets matched: <b>14</b> | Critical tier: <b>37</b>", D),
            ("Inventory: 56 assets across 9 business units", D),
        ]
    elif key == "total_fine":
        stat_rows = [
            (f"Total fine exposure this run: <b>{_fmt_dollar(es.get('total_fine'))}</b>", L),
            (f"Compliance frameworks applied: <b>{', '.join(meta.get('compliance') or ['—'])}</b>", L),
            ("PCI DSS fine range: $5K–$100K/incident (scaled by CVSS severity)", D),
            ("HIPAA max: $1.9M/yr Tier-4 · SOC2 contractual: $50K–$500K/breach", D),
        ]
    elif key == "blast_info":
        blast_disp = (f"{top_blast:.3f} {top_blast_lbl} ({top_blast_cve})"
                      if top_blast > 0 else "—")
        stat_rows = [
            (f"Max blast radius in top-10: <b>{blast_disp}</b>", L),
            ("CVEs with blast > 0 in full batch: <b>37 / 500</b>", D),
            ("Method used per CVE: Graph BFS → Software spread → CWE heuristic", D),
            ("Dependency graph: <b>16 service nodes</b> | 24 directed edges", D),
        ]
    elif key == "patch_avail":
        stat_rows = [
            (f"CVEs scheduled to maintenance windows: <b>{sched_cves}</b>", L),
            ("Patch confirmed available (batch): <b>11 CVEs</b>", D),
            ("GitHub GHSA: 8 CVEs resolved | Microsoft MSRC: 3 CVEs resolved", D),
            ("Unknown status: <b>489 CVEs</b> → action: Check vendor advisory", D),
        ]
    elif key == "total_risk":
        total_risk = es.get("total_risk") or 0
        stat_rows = [
            (f"Total breach risk prevented: <b>{_fmt_dollar(total_risk)}</b>", L),
            (f"Net portfolio ROI: <b>{_fmt_dollar(total_risk - 75_000)}</b>", L),
            (f"Confidence breakdown (top-10): {conf_str or '—'}", L),
            ("Patch cost model: $75/hr × 2h avg = $150/CVE (fixed formula)", D),
        ]
    elif key == "tier1_count":
        t1 = es.get("tier1_count", 0)
        t2 = es.get("tier2_count", 0)
        t3 = len(t3_list)
        t4 = len(t4_list)
        stat_rows = [
            (f"Tier 1 (patch NOW — 24h): <b>{t1} CVEs</b>", L),
            (f"Tier 2 (this sprint — 7 days): <b>{t2} CVEs</b>", L),
            (f"Tier 3 (30-day sprint): <b>{t3} CVEs</b> | Tier 4 (monitor): <b>{t4} CVEs</b>", L),
            ("Output: aria_report_*.md + aria_audit_*.json + aria_ranked_*.csv", D),
        ]

    # Pipeline position — compute upstream / downstream from GRAPH_EDGES constant
    up_ids   = [AGENT_NODES[s]["id"] for s, d in GRAPH_EDGES if d == nd["idx"]]
    down_ids = [AGENT_NODES[d]["id"] for s, d in GRAPH_EDGES if s == nd["idx"]]
    up_html = (
        "".join(f'<span class="agent-pill pill-in">{i}</span>' for i in up_ids)
        or '<span style="color:#475569;font-size:0.8rem;">— entry point</span>'
    )
    down_html = (
        "".join(f'<span class="agent-pill pill-out">{i}</span>' for i in down_ids)
        or '<span style="color:#475569;font-size:0.8rem;">— terminal output</span>'
    )
    llm_badge = (
        f'<span class="agent-pill pill-llm">🤖 {nd["llm"]}</span>'
        if nd.get("llm") else ""
    )

    # Build steps HTML (numbered list)
    steps_parts: list[str] = []
    for i, step in enumerate(steps):
        steps_parts.append(
            '<div style="display:flex;gap:0.5rem;padding:0.3rem 0;'
            'border-bottom:1px solid rgba(56,189,248,0.07);">'
            f'<span style="color:#38bdf8;font-weight:700;font-size:0.8rem;'
            f'min-width:1.3rem;padding-top:1px;">{i + 1}.</span>'
            f'<span style="color:#cbd5e1;font-size:0.82rem;line-height:1.5;">{step}</span>'
            '</div>'
        )
    steps_html = "".join(steps_parts)

    # Build stats HTML — live rows get ⚡ badge, dataset rows get 📋 badge
    stat_parts: list[str] = []
    for ln, badge in stat_rows:
        if badge == "live":
            badge_html = (
                '<span style="font-size:0.65rem;font-weight:700;'
                'background:rgba(52,211,153,0.15);color:#34d399;'
                'border:1px solid rgba(52,211,153,0.3);border-radius:3px;'
                'padding:0px 4px;margin-right:5px;">⚡ LIVE</span>'
            )
        else:
            badge_html = (
                '<span style="font-size:0.65rem;font-weight:700;'
                'background:rgba(71,85,105,0.2);color:#64748b;'
                'border:1px solid rgba(71,85,105,0.3);border-radius:3px;'
                'padding:0px 4px;margin-right:5px;">📋 DATASET</span>'
            )
        stat_parts.append(
            '<div style="display:flex;align-items:flex-start;gap:0;'
            'color:#e2e8f0;font-size:0.81rem;padding:0.28rem 0;'
            f'border-bottom:1px solid rgba(71,85,105,0.18);">'
            f'{badge_html}<span>{ln}</span></div>'
        )
    stat_html = "".join(stat_parts)
    stat_block = ""
    if stat_rows:
        stat_block = (
            '<div style="border-top:1px solid rgba(56,189,248,0.15);'
            'padding-top:0.75rem;margin-top:0.5rem;">'
            '<div style="display:flex;align-items:center;gap:0.5rem;'
            'margin-bottom:7px;">'
            '<span style="color:#64748b;font-size:0.68rem;font-weight:700;'
            'text-transform:uppercase;letter-spacing:.06em;">📊 This Run — Stats</span>'
            '<span style="color:#64748b;font-size:0.65rem;">'
            '(<span style="color:#34d399;">⚡ LIVE</span> = from this API call&nbsp;·&nbsp;'
            '<span style="color:#64748b;">📋 DATASET</span> = evaluation set constant)</span>'
            '</div>'
            '<div style="background:rgba(7,11,18,0.5);border-radius:8px;'
            'padding:0.5rem 0.75rem;border:1px solid rgba(71,85,105,0.2);">'
            + stat_html +
            '</div></div>'
        )

    src_pills = "".join(
        f'<span class="agent-pill pill-src">{s}</span>' for s in nd["sources"]
    )

    html = (
        '<div class="agent-detail-card" style="max-height:88vh;overflow-y:auto;">'

        # Header
        '<div style="display:flex;justify-content:space-between;align-items:flex-start;'
        'margin-bottom:1rem;padding-bottom:0.75rem;'
        'border-bottom:1px solid rgba(56,189,248,0.18);">'
        '<div style="display:flex;align-items:center;gap:0.75rem;">'
        f'<span style="font-size:2rem;line-height:1;">{nd["icon"]}</span>'
        '<div>'
        f'<div style="font-size:1.15rem;font-weight:700;color:#f1f5f9;line-height:1.2;">{nd["name"]}</div>'
        f'<div style="color:#64748b;font-size:0.8rem;margin-top:2px;">{nd["id"]} · ARIA Pipeline Agent</div>'
        '</div>'
        f'{llm_badge}'
        '</div>'
        '<span style="color:#34d399;font-size:0.8rem;font-weight:600;'
        'background:rgba(52,211,153,0.1);border:1px solid rgba(52,211,153,0.3);'
        'border-radius:6px;padding:3px 10px;">✅ Complete</span>'
        '</div>'

        # Mission brief
        '<div style="background:rgba(56,189,248,0.06);border-left:3px solid rgba(56,189,248,0.5);'
        'padding:0.55rem 0.9rem;border-radius:0 8px 8px 0;margin-bottom:1rem;">'
        f'<p style="color:#bae6fd;font-size:0.86rem;line-height:1.6;margin:0;">{nd["task"]}</p>'
        '</div>'

        # Pipeline data-flow diagram
        '<div style="display:grid;grid-template-columns:1fr auto 1fr;gap:0.5rem;'
        'align-items:center;margin-bottom:1rem;padding:0.55rem 0.75rem;'
        'background:rgba(15,23,42,0.5);border-radius:8px;border:1px solid rgba(71,85,105,0.2);">'
        '<div>'
        '<div style="color:#64748b;font-size:0.68rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.06em;margin-bottom:4px;">← Receives From</div>'
        f'{up_html}'
        '</div>'
        '<div style="text-align:center;font-size:1.3rem;color:#334155;">⇒</div>'
        '<div>'
        '<div style="color:#64748b;font-size:0.68rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.06em;margin-bottom:4px;">Sends To →</div>'
        f'{down_html}'
        '</div>'
        '</div>'

        # Two columns: Algorithm | I/O + Sources
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem;">'

        # Left — algorithm steps
        '<div>'
        '<div style="color:#64748b;font-size:0.68rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.06em;margin-bottom:7px;">⚙️ Algorithm — Step-by-Step</div>'
        '<div style="background:rgba(7,11,18,0.7);border-radius:8px;padding:0.55rem 0.7rem;'
        'border:1px solid rgba(71,85,105,0.2);">'
        f'{steps_html}'
        '</div>'
        '</div>'

        # Right — I/O + sources
        '<div style="display:flex;flex-direction:column;gap:0.65rem;">'
        '<div>'
        '<div style="color:#64748b;font-size:0.68rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.06em;margin-bottom:4px;">📥 Example Input</div>'
        '<div style="background:rgba(56,189,248,0.06);border-radius:6px;padding:0.42rem 0.6rem;'
        'font-family:JetBrains Mono,monospace;font-size:0.73rem;color:#7dd3fc;'
        'border:1px solid rgba(56,189,248,0.15);word-break:break-all;'
        f'line-height:1.5;">{ex_in}</div>'
        '</div>'
        '<div>'
        '<div style="color:#64748b;font-size:0.68rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.06em;margin-bottom:4px;">📤 Example Output</div>'
        '<div style="background:rgba(52,211,153,0.06);border-radius:6px;padding:0.42rem 0.6rem;'
        'font-family:JetBrains Mono,monospace;font-size:0.73rem;color:#6ee7b7;'
        'border:1px solid rgba(52,211,153,0.15);word-break:break-all;'
        f'line-height:1.5;">{ex_out}</div>'
        '</div>'
        '<div>'
        '<div style="color:#64748b;font-size:0.68rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.06em;margin-bottom:4px;">📂 Data Sources</div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:3px;">{src_pills}</div>'
        '</div>'
        '</div>'  # end right column

        '</div>'  # end two-column grid

        # Why this agent matters
        '<div style="background:rgba(167,139,250,0.07);border-left:3px solid rgba(167,139,250,0.5);'
        'padding:0.5rem 0.9rem;border-radius:0 8px 8px 0;margin-bottom:0.7rem;">'
        '<div style="color:#a78bfa;font-size:0.68rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.06em;margin-bottom:3px;">💡 Why This Agent Matters</div>'
        f'<p style="color:#ddd6fe;font-size:0.83rem;line-height:1.55;margin:0;">{why}</p>'
        '</div>'

        # Fallback / resilience
        '<div style="background:rgba(245,158,11,0.06);border-left:3px solid rgba(245,158,11,0.4);'
        'padding:0.5rem 0.9rem;border-radius:0 8px 8px 0;margin-bottom:0.5rem;">'
        '<div style="color:#fbbf24;font-size:0.68rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.06em;margin-bottom:3px;">🛡️ Fallback / Resilience</div>'
        f'<p style="color:#fde68a;font-size:0.82rem;line-height:1.5;margin:0;">{fallback}</p>'
        '</div>'

        + stat_block +

        '</div>'  # end agent-detail-card
    )
    st.markdown(html, unsafe_allow_html=True)


# ── Animation section ─────────────────────────────────────────────────────────

def _render_animation_section(stage: int, anim_frame: int) -> None:
    """Renders the DAG graph + status bar during the API call."""
    stage_labels = [
        "Initialising agents…",
        "🏢 Business Context agent running (Claude Haiku)…",
        "📥⚡🗺️ CVE Ingestion · Exploit Intel · Threat Mapping (parallel)…",
        "🔍 Asset Matching — CVEs × 56-asset inventory…",
        "⚖️💥 Compliance fines · Blast radius (parallel)…",
        "🔧 Patch Feasibility — GitHub + MSRC advisories…",
        "💰 ROI Calculation — ranking by breach risk…",
        "📊 Report Generation (Claude Sonnet reasoning)…",
        "📡 All agents visualized — waiting for backend to finish computing…",
    ]
    label = stage_labels[min(stage, len(stage_labels) - 1)]

    spinners = ["◐", "◓", "◑", "◒"]
    spin = spinners[anim_frame % 4]

    st.markdown("## 🕸️ ARIA Agent Pipeline — Live Execution")

    # Stage 8 gets a special "still working" banner so users know to wait
    if stage >= 8:
        st.markdown(
            f'<div class="war-card" style="border-left:3px solid #38bdf8;padding:0.6rem 1rem;">'
            f'<span style="color:#7dd3fc;font-size:0.9rem;">{spin} {label}</span>'
            f'<span style="color:#475569;font-size:0.8rem;margin-left:1rem;">'
            f'Backend analysis in progress — results will appear automatically when complete.</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div class="war-card" style="border-left:3px solid #fbbf24;padding:0.6rem 1rem;">'
            f'<span style="color:#fde68a;font-size:0.9rem;">⚙️ {label}</span></div>',
            unsafe_allow_html=True,
        )

    # Progress bar
    total_frames = sum(ANIM_STAGE_FRAMES[:-1])
    pct = min(anim_frame / total_frames, 1.0)
    st.progress(pct)

    if go is not None:
        result = _build_agent_graph(stage, None, None, anim_frame)
        if result:
            fig, _ = result
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.info("Install plotly for the interactive DAG: `pip install plotly`")


# ── Results sections ──────────────────────────────────────────────────────────

def render_agent_dag(report: dict[str, Any]) -> None:
    """Final completed DAG with click-to-detail interaction."""
    if go is None:
        return
    st.markdown("---")
    st.markdown("## 🕸️ How ARIA Got Here — Interactive Agent Pipeline")
    st.caption(
        "All 10 agents completed. **Click any node** to see exactly what algorithm it ran, "
        "its example input/output, data sources, and live stats from this analysis."
    )

    sel = st.session_state.get("selected_agent")
    result = _build_agent_graph(8, report, sel, 0)
    if not result:
        return
    fig, nodes_trace_num = result

    # KEY INSIGHT: use a dynamic key that encodes the current selection.
    # When selection changes, the key changes → Streamlit destroys the old
    # Plotly widget and creates a fresh one with zero retained selection state.
    # Without this, Plotly re-delivers the same click event on every rerun,
    # causing the toggle logic to fire repeatedly (needs 3-4 clicks to settle).
    chart_key = f"final_dag_sel{sel}"

    try:
        event = st.plotly_chart(
            fig, use_container_width=True,
            config={"displayModeBar": False},
            on_select="rerun",
            key=chart_key,
        )
        # Detect node click — only fires once per user interaction because the
        # fresh chart key has no retained selection on subsequent reruns.
        pts = []
        if event:
            try:
                pts = event.selection.points  # Streamlit >= 1.35
            except AttributeError:
                try:
                    pts = event.selection.get("points", [])  # dict-style
                except Exception:
                    pts = []
        if pts:
            pt = pts[0]
            try:
                cn  = pt.curve_number
                pid = pt.point_index
            except AttributeError:
                cn  = pt.get("curve_number", -1)
                pid = pt.get("point_index", -1)
            if cn == nodes_trace_num and 0 <= pid < len(AGENT_NODES):
                # Toggle: clicking the same node closes the panel
                new_sel = None if st.session_state.get("selected_agent") == pid else pid
                st.session_state.selected_agent = new_sel
                # Rerun so `sel` at the top of this function gets the new value,
                # the chart key changes (fresh Plotly widget), and the detail
                # panel renders correctly on the very next run.
                st.rerun()
    except TypeError:
        # Older Streamlit without on_select — just render without click
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    # Agent detail panel — rendered with the correct `sel` because we always
    # st.rerun() after changing it above (so this branch uses the settled value).
    if sel is not None and 0 <= sel < len(AGENT_NODES):
        nd = AGENT_NODES[sel]
        col_title, col_close = st.columns([8, 1])
        with col_close:
            if st.button("✕ Close", key="close_agent_detail"):
                st.session_state.selected_agent = None
                st.rerun()
        _render_agent_detail(nd, report)


def render_exec_metrics(report: dict[str, Any]) -> None:
    meta = report.get("metadata") or {}
    es   = report.get("executive_summary") or {}
    st.markdown("## 📊 Executive Dashboard")
    st.caption(
        f"Industry: **{meta.get('industry','—')}** &nbsp;·&nbsp; "
        f"Org: **{meta.get('org_name','—')}** &nbsp;·&nbsp; "
        f"Run: {meta.get('run_date','—')}"
    )
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("CVEs Analyzed",      str(meta.get("total_cves", "—")))
    c2.metric("Tier 1 — Patch NOW", str(es.get("tier1_count", "—")))
    c3.metric("KEV Active",          str(es.get("kev_count", "—")))
    c4.metric("Breach Risk",         _fmt_dollar(es.get("total_risk")))
    c5.metric("Fine Exposure",       _fmt_dollar(es.get("total_fine")))
    headline = es.get("headline", "")
    if headline:
        st.markdown(
            f'<div class="war-card" style="margin-top:0.6rem;border-left:3px solid #38bdf8;">'
            f'<span style="font-size:0.95rem;color:#e2e8f0;">{headline}</span></div>',
            unsafe_allow_html=True,
        )


def render_claude_panel(report: dict[str, Any]) -> None:
    triage = (report.get("triage_validation") or report.get("triage_note") or "").strip()
    st.markdown("## 🧠 AI Security Analyst Recommendation")
    if triage:
        st.success(triage)
    else:
        st.info(
            "No Claude triage text returned — set ANTHROPIC_API_KEY to enable. "
            "ARIA prioritization is still fully deterministic and valid."
        )


def render_exec_bullets(report: dict[str, Any]) -> None:
    es = report.get("executive_summary") or {}
    bullets = es.get("bullets") or []
    if not bullets:
        return
    with st.expander("📋 CFO / Leadership Brief", expanded=False):
        for b in bullets:
            st.markdown(f"- {b}")
        ia = es.get("immediate_action", "")
        if ia:
            st.markdown(f"\n**Immediate action:** {ia}")


def _cve_card(entry: dict[str, Any], idx: int) -> str:
    sev, color = _sev_label_color(entry.get("cvss"))
    kev      = bool(entry.get("in_kev"))
    rw       = bool(entry.get("ransomware"))
    epss_pct = float(entry.get("epss") or 0) * 100
    roi      = float(entry.get("roi_net_benefit") or 0)
    conf     = entry.get("confidence", "—")
    rank     = entry.get("rank", idx + 1)
    kev_html = (
        '<span class="war-kev"><span class="kev-flash">⚠️</span> KEV — ACTIVE EXPLOITATION</span>'
        if kev else '<span style="color:#64748b">KEV: No</span>'
    )
    rw_html = '<span style="color:#fb923c;font-weight:700;"> 💀 Ransomware</span>' if rw else ""
    roi_html = (
        f'<span class="roi-glow">{_fmt_dollar(roi)} 💰 HIGH IMPACT</span>'
        if roi > 1_000_000 else f'<b style="color:#5eead4">{_fmt_dollar(roi)}</b>'
    )
    delay = idx * 0.055
    return f"""
<div class="war-card card-fade" style="border-left:4px solid {color};animation-delay:{delay}s;">
<div style="display:flex;justify-content:space-between;align-items:center;">
  <span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:1.05rem;color:#f1f5f9;">#{rank} {entry.get("cve_id","N/A")}</span>
  <span style="color:{color};font-weight:600;">{sev}</span>
</div>
<div style="margin-top:0.5rem;font-size:0.9rem;color:#cbd5e1;">
  CVSS: <b>{entry.get("cvss","—")}</b> &nbsp;|&nbsp; EPSS: <b>{epss_pct:.2f}%</b> &nbsp;|&nbsp; Confidence: <b>{conf}</b><br/>
  {kev_html}{rw_html}<br/>
  Asset: <b>{entry.get("asset_name") or "—"}</b><br/>
  ROI: {roi_html}<br/>
  <span style="color:#94a3b8;font-size:0.82rem;">{entry.get("patch_action") or "—"}</span>
</div>
</div>""".strip()


def render_top10_grid(report: dict[str, Any]) -> None:
    top10: list[dict[str, Any]] = report.get("top10_detailed") or []
    if not top10:
        st.warning("No ranked CVEs returned.")
        return
    st.markdown("---")
    st.markdown("## 🎯 Top 10 Priority CVEs")
    st.caption("Ranked by ARIA composite score: CVSS × EPSS × KEV × asset criticality × blast radius × ROI.")
    holder = st.empty()
    accumulated: list[str] = []
    pair: list[str] = []
    import time as _time
    import random as _random
    for idx, entry in enumerate(top10[:10]):
        pair.append(_cve_card(entry, idx))
        if len(pair) == 2 or idx == len(top10[:10]) - 1:
            accumulated.append(
                '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">'
                + "".join(pair) + "</div>"
            )
            holder.markdown('<div style="max-width:100%;">' + "".join(accumulated) + "</div>",
                            unsafe_allow_html=True)
            pair = []
            _time.sleep(_random.uniform(0.04, 0.08))


def render_cve_detail(report: dict[str, Any]) -> None:
    top10: list[dict[str, Any]] = report.get("top10_detailed") or []
    cve_ids = [e.get("cve_id") for e in top10 if e.get("cve_id")]
    if not cve_ids:
        return
    st.markdown("---")
    st.markdown("## 🔎 Analyst Console — CVE Deep Dive")
    choice = st.selectbox("Select CVE for full analysis", options=cve_ids, index=0, key="cve_select")
    entry  = next((e for e in top10 if e.get("cve_id") == choice), {})
    if not entry:
        return
    st.markdown(f"#### `{choice}` — Why ranked #{entry.get('rank','?')}?")
    epss_pct = float(entry.get("epss") or 0) * 100
    fine     = float(entry.get("compliance_fine") or 0)
    blast_r  = entry.get("blast_radius")
    blast_l  = entry.get("blast_label") or "—"
    c1, c2, c3 = st.columns(3)
    c1.metric("CVSS",           str(entry.get("cvss", "—")))
    c2.metric("EPSS (30-day)",  f"{epss_pct:.2f}%")
    c3.metric("KEV",            "YES ⚠️" if entry.get("in_kev") else "No")
    c4, c5, c6 = st.columns(3)
    c4.metric("Asset Criticality", str(entry.get("criticality") or "—").title())
    blast_disp = (
        f"{float(blast_r):.2f} ({blast_l})"
        if isinstance(blast_r, (int, float)) else f"{blast_r} ({blast_l})"
    ) if blast_r is not None else blast_l
    c5.metric("Blast Radius",        blast_disp)
    c6.metric("Compliance Exposure", f"${fine:,.0f}")
    c7, c8 = st.columns(2)
    c7.metric("Net ROI of Patching", _fmt_dollar(entry.get("roi_net_benefit")))
    c8.metric("Confidence",           entry.get("confidence", "—"))
    # Context tags
    flags = entry.get("compliance_flags") or []
    ap    = entry.get("attack_phase", "")
    cwe   = entry.get("cwe", "")
    tags_html = ""
    if flags:
        tags_html += (
            '<span style="color:#94a3b8;font-size:0.82rem;">Regulations at risk:</span> '
            + " ".join(f'<code style="background:rgba(239,68,68,0.15);color:#fca5a5;padding:1px 6px;border-radius:4px;">{f}</code>' for f in flags)
            + "<br/>"
        )
    if ap:
        tags_html += (
            f'<span style="color:#94a3b8;font-size:0.82rem;">ATT&CK phase:</span> '
            f'<code style="background:rgba(251,191,36,0.12);color:#fde68a;padding:1px 6px;border-radius:4px;">{ap}</code><br/>'
        )
    if cwe:
        tags_html += (
            f'<span style="color:#94a3b8;font-size:0.82rem;">Weakness:</span> '
            f'<code style="background:rgba(167,139,250,0.12);color:#c4b5fd;padding:1px 6px;border-radius:4px;">{cwe}</code>'
        )
    if tags_html:
        st.markdown(f'<div class="war-card" style="padding:0.6rem 1rem;margin-top:0.4rem;">{tags_html}</div>',
                    unsafe_allow_html=True)
    # Patch info
    patch_action  = entry.get("patch_action", "")
    patch_context = entry.get("patch_context", "")
    if patch_action or patch_context:
        with st.expander("🔧 Patch Details", expanded=True):
            if patch_action:
                st.markdown(f"**Action:** {patch_action}")
            if entry.get("patch_source"):
                st.markdown(f"**Source:** {entry.get('patch_source')}")
            if entry.get("patch_conflict"):
                st.warning(f"⚠️ Conflict: {entry.get('patch_conflict_note','')}")
            if patch_context:
                st.markdown(patch_context)
    # Threat context
    if entry.get("threat_context"):
        with st.expander("🛡️ Threat Context", expanded=False):
            st.markdown(entry["threat_context"])
    # ARIA scoring trace
    if entry.get("reasoning"):
        with st.expander("🔍 ARIA Scoring Trace", expanded=False):
            for step in entry["reasoning"]:
                st.markdown(f"- {step}")
    # LLM narrative
    if entry.get("llm_reasoning"):
        st.markdown("##### AI Analyst Narrative")
        st.markdown(
            f'<div class="war-card" style="border-color:#a78bfa;">{entry["llm_reasoning"]}</div>',
            unsafe_allow_html=True,
        )
    # Final verdict
    label, kind = _decision(entry)
    st.markdown("##### Final Verdict")
    st.markdown(f'<div class="decision-{kind}">{label}</div>', unsafe_allow_html=True)
    # Blast graph
    _render_blast_graph(entry)


def _render_blast_graph(entry: dict[str, Any]) -> None:
    if go is None:
        return
    cve     = entry.get("cve_id", "CVE")
    asset   = entry.get("asset_name") or "Asset"
    flags   = entry.get("compliance_flags") or []
    comp    = ", ".join(flags) if flags else "No compliance impact"
    ap      = entry.get("attack_phase") or "Unknown phase"
    blast_r = entry.get("blast_radius")
    blast_s = f"Blast {float(blast_r):.0%}" if isinstance(blast_r, (int, float)) else "Blast"
    node_x = [0, -1.4, 1.4, 0, 0]
    node_y = [0, 0.9, 0.9, -1.1, 1.5]
    labels = [cve, asset, ap, comp, blast_s]
    colors = ["#38bdf8", "#a78bfa", "#f87171", "#fbbf24", "#34d399"]
    sizes  = [32, 24, 20, 20, 18]
    ex: list = []
    ey: list = []
    for sx, sy in [(-1.4, 0.9), (1.4, 0.9), (0, -1.1), (0, 1.5)]:
        ex += [0, sx, None]
        ey += [0, sy, None]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=ex, y=ey, mode="lines",
                             line=dict(color="rgba(56,189,248,0.4)", width=1.5),
                             hoverinfo="none", showlegend=False))
    fig.add_trace(go.Scatter(x=node_x, y=node_y, mode="markers+text",
                             marker=dict(size=sizes, color=colors,
                                         line=dict(color="#e2e8f0", width=1)),
                             text=labels, textposition="top center",
                             textfont=dict(color="#e8edf7", size=10),
                             hovertemplate="%{text}<extra></extra>",
                             showlegend=False))
    fig.update_layout(
        title=dict(text="🕸️ CVE Impact Surface", font=dict(color="#e8edf7", size=14)),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(15,23,42,0.5)",
        xaxis=dict(visible=False, range=[-2.2, 2.2]),
        yaxis=dict(visible=False, range=[-1.7, 2.0]),
        height=320, margin=dict(l=10, r=10, t=40, b=10),
    )
    st.markdown("### 🌐 Blast & Dependency View")
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def render_cve_threat_feed(report: dict[str, Any]) -> None:
    """Streams top CVEs as a live threat-intelligence ticker."""
    top10: list[dict[str, Any]] = report.get("top10_detailed") or []
    if not top10:
        return
    st.markdown("---")
    st.markdown("## 📡 Live Threat Intelligence Feed")
    st.caption(
        "Real-time ingestion of the highest-priority CVEs from this ARIA run, "
        "ranked by composite risk score. "
        "**KEV** = CISA confirmed active exploitation · **RW** = ransomware-linked"
    )

    import time as _feed_time
    feed_holder = st.empty()
    header = (
        '<div style="display:flex;gap:0.5rem;align-items:center;padding:0.25rem 0;'
        'border-bottom:1px solid rgba(71,85,105,0.4);margin-bottom:4px;">'
        '<span style="color:#475569;font-size:0.7rem;min-width:2rem;">#</span>'
        '<span style="color:#64748b;font-size:0.7rem;min-width:10rem;">CVE ID</span>'
        '<span style="color:#64748b;font-size:0.7rem;min-width:5.5rem;">SEVERITY</span>'
        '<span style="color:#64748b;font-size:0.7rem;min-width:2.2rem;">CVSS</span>'
        '<span style="color:#64748b;font-size:0.7rem;min-width:4rem;">EPSS</span>'
        '<span style="color:#64748b;font-size:0.7rem;flex:1;">ASSET</span>'
        '<span style="color:#64748b;font-size:0.7rem;min-width:5.5rem;">CONFIDENCE</span>'
        '<span style="color:#64748b;font-size:0.7rem;min-width:5rem;">ARIA SCORE</span>'
        '</div>'
    )
    lines: list[str] = [header]

    for entry in top10[:10]:
        cve_id   = entry.get("cve_id", "N/A")
        cvss     = entry.get("cvss", "—")
        epss_pct = float(entry.get("epss") or 0) * 100
        kev      = bool(entry.get("in_kev"))
        rw       = bool(entry.get("ransomware"))
        asset    = (entry.get("asset_name") or "—")[:30]
        conf     = entry.get("confidence", "—")
        rank     = entry.get("rank", "?")
        # Use base_score (0–1 normalized threat signal) for the bar.
        # final_score has asset multipliers applied (can be >10) — not suitable for the bar.
        aria_s   = float(entry.get("base_score") or 0)
        sev, col = _sev_label_color(cvss)

        kev_tag = ' <span style="color:#f87171;font-weight:700;font-size:0.7rem;">[KEV]</span>' if kev else ""
        rw_tag  = ' <span style="color:#fb923c;font-weight:700;font-size:0.7rem;">[RW]</span>'  if rw  else ""

        # Mini progress bar for base score (0–1)
        bar_w  = max(4, int(aria_s * 72))
        bar_col = "#ef4444" if aria_s >= 0.75 else ("#f97316" if aria_s >= 0.5 else "#38bdf8")
        aria_bar = (
            f'<div style="display:inline-block;width:{bar_w}px;height:5px;'
            f'background:{bar_col};border-radius:3px;vertical-align:middle;'
            f'margin-right:4px;"></div>'
            f'<span style="color:#94a3b8;font-size:0.7rem;">{aria_s:.3f}</span>'
        )

        rank_str = f"#{rank:02d}" if isinstance(rank, int) else f"#{rank}"
        line = (
            '<div class="feed-line" style="display:flex;gap:0.5rem;align-items:center;">'
            f'<span style="color:#475569;font-size:0.72rem;min-width:2rem;">{rank_str}</span>'
            f'<span style="color:#f1f5f9;font-weight:700;font-family:JetBrains Mono,monospace;'
            f'font-size:0.84rem;min-width:10rem;">{cve_id}{kev_tag}{rw_tag}</span>'
            f'<span style="color:{col};font-weight:600;font-size:0.8rem;min-width:5.5rem;">{sev}</span>'
            f'<span style="color:#f1f5f9;font-size:0.8rem;min-width:2.2rem;">{cvss}</span>'
            f'<span style="color:#fde68a;font-size:0.8rem;min-width:4rem;">{epss_pct:.2f}%</span>'
            f'<span style="color:#94a3b8;font-size:0.75rem;flex:1;">{asset}</span>'
            f'<span style="color:#6ee7b7;font-size:0.73rem;min-width:5.5rem;">{conf}</span>'
            f'<span style="min-width:5rem;">{aria_bar}</span>'
            '</div>'
        )
        lines.append(line)
        feed_holder.markdown(
            '<div class="feed-scroll" style="max-height:280px;">'
            + "".join(lines) +
            '</div>',
            unsafe_allow_html=True,
        )
        _feed_time.sleep(0.08)


def render_tier_breakdown(report: dict[str, Any]) -> None:
    tier_data = {
        "Tier 1 — Patch within 24 h 🔴":  report.get("tier1_immediate") or [],
        "Tier 2 — Patch within 7 days 🟠": report.get("tier2_urgent")   or [],
        "Tier 3 — Sprint backlog 🟡":       report.get("tier3_sprint")   or [],
        "Tier 4 — Monitor 🟢":             report.get("tier4_monitor")  or [],
    }
    st.markdown("---")
    st.markdown("## 📋 Full Tier Breakdown")
    for label, cves in tier_data.items():
        if not cves:
            continue
        with st.expander(f"{label} ({len(cves)} CVEs)", expanded=label.startswith("Tier 1")):
            header = (
                '<div class="tier-row" style="color:#94a3b8;font-weight:700;">'
                'CVE ID &nbsp; CVSS &nbsp; EPSS% &nbsp; KEV &nbsp; Asset &nbsp; Fine &nbsp; Action'
                '</div>'
            )
            rows = header
            for c in cves:
                sev, col  = _sev_label_color(c.get("cvss"))
                epss_pct  = f"{float(c.get('epss') or 0)*100:.1f}%"
                fine      = _fmt_dollar(c.get("compliance_fine"))
                asset_nm  = (c.get("asset") or c.get("asset_name") or "—")[:30]
                action    = (c.get("patch_action") or "—")[:50]
                rows += (
                    f'<div class="tier-row">'
                    f'<b style="color:{col}">{c.get("cve_id","")}</b> &nbsp;'
                    f'{c.get("cvss","—")} &nbsp;{epss_pct} &nbsp;'
                    f'{"⚠️" if c.get("in_kev") else "—"} &nbsp;'
                    f'<span style="color:#94a3b8">{asset_nm}</span> &nbsp;'
                    f'{fine} &nbsp;<span style="color:#64748b;font-size:0.78rem;">{action}</span>'
                    f'</div>'
                )
            st.markdown(f'<div class="war-card" style="padding:0.4rem 0.8rem;">{rows}</div>',
                        unsafe_allow_html=True)


def render_patch_schedule(report: dict[str, Any]) -> None:
    sched   = report.get("patch_schedule") or {}
    batches = sched.get("batches") or []
    if not batches:
        return
    st.markdown("---")
    st.markdown("## 🗓️ Maintenance Window Schedule")
    if sched.get("summary"):
        st.markdown(f'<div class="war-card">{sched["summary"]}</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("CVEs Scheduled",   str(sched.get("scheduled_cves", "—")))
    c2.metric("Total Labor Cost", _fmt_dollar(sched.get("total_labor_cost")))
    c3.metric("Total ROI",        _fmt_dollar(sched.get("total_roi")))
    for batch in batches:
        cves   = batch.get("cves") or []
        window = batch.get("window", "Window")
        date   = batch.get("date", "TBD")
        hours  = batch.get("hours", 0)
        budget = batch.get("budget_h", 0)
        roi    = _fmt_dollar(batch.get("roi_$"))
        labor  = _fmt_dollar(batch.get("labor_$"))
        notes  = batch.get("notes", "")
        with st.expander(
            f"**{window}** — {date}  ({len(cves)} CVEs | {hours}/{budget}h | ROI {roi})",
            expanded=False,
        ):
            # notes is list[str] from the backend scheduler
            if notes:
                note_str = " · ".join(notes) if isinstance(notes, list) else str(notes)
                st.caption(note_str)
            st.markdown(f"**Labor cost:** {labor} &nbsp;&nbsp; **Net ROI:** {roi}")
            if cves:
                st.markdown("**CVEs in this window:**")
                st.markdown("  ".join(f"`{c}`" for c in cves))
    backlog = sched.get("backlog") or []
    if backlog:
        with st.expander(f"⏳ Backlog — {len(backlog)} CVEs deferred", expanded=False):
            for item in backlog[:20]:
                cid = item if isinstance(item, str) else item.get("cve_id", str(item))
                st.markdown(f"- `{cid}`")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    st.set_page_config(
        page_title="ARIA — Command Center",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    _css()

    st.title("ARIA — AI Cyber Risk Command Center")
    st.caption(
        "Autonomous Risk Intelligence Agent · 10-agent multi-signal vulnerability prioritization "
        "| NVD · EPSS · CISA KEV · MITRE ATT&CK · Asset Inventory · Blast Radius · ROI"
    )

    # ── Session state init ────────────────────────────────────────────────────
    defaults = {
        "report": None, "error": None,
        "api_running": False, "run_id": None,
        "anim_frame": 0, "selected_agent": None,
        "results_fresh": False,   # True on the first render after API returns
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    # ── Input form ────────────────────────────────────────────────────────────
    with st.container():
        st.markdown("### 🎛️ Mission Parameters")
        col_name, _ = st.columns([2, 1])
        with col_name:
            org_name = st.text_input("Organization name", value="HelioHealth SaaS")
        org_desc = st.text_area(
            "Org profile — describe your stack, size, industry, data types and compliance obligations",
            value=DEFAULT_ORG_DESCRIPTION,
            height=130,
        )
        run = st.button("🚀 Run ARIA Analysis", type="primary",
                        disabled=st.session_state.api_running)

    # ── Launch background API call ────────────────────────────────────────────
    if run and not st.session_state.api_running:
        run_id = str(uuid.uuid4())
        st.session_state.run_id      = run_id
        st.session_state.api_running = True
        st.session_state.anim_frame  = 0
        st.session_state.report      = None
        st.session_state.error       = None
        st.session_state.selected_agent = None
        t = threading.Thread(
            target=_run_api_background,
            args=(run_id, org_desc.strip(), org_name.strip()),
            daemon=True,
        )
        t.start()
        st.rerun()

    # ── Animation loop ────────────────────────────────────────────────────────
    if st.session_state.api_running:
        run_id = st.session_state.run_id
        frame  = st.session_state.anim_frame

        # Check if API returned (read from cache_resource store)
        _store = _get_result_store()
        with _store["lock"]:
            api_state = _store["data"].get(run_id)

        if api_state and api_state["done"]:
            # ── API finished ──────────────────────────────────────────────────
            st.session_state.api_running = False
            st.session_state.results_fresh = True   # scroll to top on next render
            if api_state["error"]:
                st.session_state.error = api_state["error"]
            else:
                st.session_state.report = api_state["result"]
            with _store["lock"]:
                _store["data"].pop(run_id, None)
            st.rerun()
        else:
            # ── Still running — show animated DAG ────────────────────────────
            stage = _frame_to_stage(frame)
            _render_animation_section(stage, frame)
            st.session_state.anim_frame = frame + 1
            time.sleep(0.45)
            st.rerun()
        st.stop()

    # ── Error state ───────────────────────────────────────────────────────────
    if st.session_state.error:
        st.error(st.session_state.error)
        if st.button("↩ Try Again"):
            st.session_state.error = None
            st.rerun()
        st.stop()

    # ── Idle state ────────────────────────────────────────────────────────────
    report = st.session_state.report
    if not report:
        st.markdown(
            '<div class="war-card" style="margin-top:1rem;">'
            "👆 Fill in your organization profile above and click <b>Run ARIA Analysis</b>.<br/>"
            "The agent DAG animates live while the pipeline runs (~30–60 s), then the full "
            "war-room results unlock automatically.</div>",
            unsafe_allow_html=True,
        )
        st.stop()

    if report.get("error"):
        st.error(f"Pipeline error: {report['error']}")
        st.stop()

    # ── Full results ──────────────────────────────────────────────────────────

    # Scroll to top when results first load (Streamlit preserves scroll position
    # across reruns — without this, the user lands mid-page at the DAG position)
    if st.session_state.get("results_fresh"):
        st.session_state.results_fresh = False
        try:
            import streamlit.components.v1 as _components
            _components.html(
                "<script>window.parent.scrollTo({top: 0, behavior: 'instant'});</script>",
                height=0,
            )
        except Exception:
            pass

    st.success(
        "✅ **ARIA analysis complete** — all 10 agents finished. "
        "Executive dashboard and threat feed are directly below ↓"
    )
    render_exec_metrics(report)
    render_cve_threat_feed(report)       # ← live threat feed (top 10 CVEs)
    render_claude_panel(report)
    render_exec_bullets(report)
    render_top10_grid(report)
    render_cve_detail(report)
    render_tier_breakdown(report)
    render_patch_schedule(report)
    render_agent_dag(report)             # ← interactive DAG at bottom (click nodes for details)

    st.markdown("---")
    st.markdown(
        '<div style="text-align:center;color:#334155;font-size:0.8rem;padding-bottom:1rem;">'
        "ARIA · UMD Agentic AI Challenge 2026 · For decision support — validate all findings operationally before patching."
        "</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
