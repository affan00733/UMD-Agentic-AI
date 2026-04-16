# ARIA — Autonomous Risk Intelligence Agent
### UMD Agentic AI Challenge 2026 · Software Vulnerability Prioritization

> **ARIA turns a 500-CVE backlog into a 4-item emergency patch list in 0.3 seconds.**
> CVSS-only tools miss 100% of confirmed-exploited CVEs in the top-10. ARIA catches 100%.

---

## What ARIA Does

Security teams receive hundreds of new CVEs every month. The standard approach — sort by CVSS score, patch from the top — is broken: 60% of breaches involve a vulnerability that had a patch available but wasn't applied (Ponemon 2023). The reason: CVSS measures theoretical severity, not actual exploitation risk.

ARIA is a 10-agent autonomous pipeline that ingests CVE data and produces a **business-risk-ranked, CFO-ready, maintenance-window-scheduled patch plan** by combining five signal layers no existing tool uses together:

| Layer | Signal | Source |
|-------|--------|--------|
| 1 | Technical severity | NVD CVSS |
| 2 | Exploitation probability | FIRST.org EPSS |
| 3 | Confirmed active exploitation | CISA KEV |
| 4 | Your asset inventory + attack blast radius | CMDB / Dependency graph |
| 5 | Regulatory fine exposure + ROI | PCI DSS, HIPAA, SOC2, IBM breach cost data |

**No competitor produces layers 4+5 from a plain-English org description with zero integration required.**

---

## Evaluation Proof

Run `python evaluate.py` — reproducible in < 60 seconds:

| Metric | ARIA | CVSS-only | EPSS-only |
|--------|------|-----------|-----------|
| **Recall@10** | **100%** | 0% | 75% |
| **Recall@5** | **100%** | 0% | 50% |
| **MRR** | **0.508** | 0.026 | 0.410 |
| **Avg rank of KEV CVEs** | **3** | 122 | 18 |

> CVSS-only misses all 4 confirmed-exploited CVEs in the top-10 patch list.
> ARIA catches all 4. A team using CVSS-only would have patched the wrong things first.

---

## Architecture — 10-Agent Pipeline

```
Input: CVE feed (NVD) + plain-English org description
       └──────────────────────────────────────────┐
                                                   ▼
                              ┌─────────────────────────────┐
                              │       ARIA Orchestrator      │
                              └──┬───────────────────────┬───┘
                                 │                       │
              ┌──────────────────┼───────────────────┐   │
              │    PARALLEL      │                   │   │
              ▼                  ▼                   ▼   ▼
        Agent 2: EPSS     Agent 3: MITRE      Agent 4: Business Context
        (exploit intel)   (ATT&CK tactics)    (Claude Haiku — NLP parsing)
              │                  │
              └──────────────────┘
                        │
                 Agent 5: Asset Matching
                 (CVE × your inventory)
                        │
              ┌─────────┴──────────┐
              │     PARALLEL       │
              ▼                    ▼
        Agent 6: Compliance   Agent 7: Blast Radius
        (PCI/HIPAA/SOC2 $)    (dependency graph BFS)
              │                    │
              └─────────┬──────────┘
                        │
                 Agent 8: Patch Feasibility
                 (GitHub + MSRC advisories)
                        │
                 Agent 9: ROI Calculation
                 ($ value of patching each CVE)
                        │
              Claude Sonnet: Triage Validation
              (senior analyst sanity check)
                        │
                 Agent 10: Report Generation
                 (Claude Sonnet — NL reasoning per CVE)
                        │
Output: Tiered patch plan + maintenance window schedule + ROI report
        (Markdown + JSON audit trail + CSV)
```

### LLM Usage Decision

| Agent | LLM | Reason |
|-------|-----|--------|
| 1–3, 5–9 | ❌ No | Deterministic structured data — must be auditable |
| 4 Business Context | ✅ Claude Haiku | Free-text NLP: "we handle patient records" → HIPAA |
| 10 Report | ✅ Claude Sonnet | 8 signals → 1 readable English sentence per CVE |
| Orchestrator | ✅ Claude Sonnet | Holistic cross-signal sanity check before CISO review |

---

## Requirements

- **Python 3.10+** (required — uses `match` statements and modern type hints)
- No API key needed for full functionality (Claude features use deterministic fallbacks)

## Quick Start (5 minutes)

### Option A — Command-line (fastest)

```bash
# 1. Install backend dependencies
cd backend/
pip3 install -r requirements.txt

# 2. Run ARIA (demo mode — no API key needed)
python3 run_aria.py

# 3. Run ARIA on your organization
python3 run_aria.py --org "We are a healthcare SaaS company serving hospitals. \
  We store patient records (PHI), process credit card payments, and run on AWS. \
  Stack: Python, React, PostgreSQL, Docker. 500 employees."
```

Output appears in `output/` as `.md` (human report), `.json` (audit trail), `.csv` (spreadsheet).

### Option B — Web UI (War Room Dashboard)

Open **two terminals**:

**Terminal 1 — start the API server:**
```bash
cd backend/
pip3 install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

**Terminal 2 — start the Streamlit UI:**
```bash
cd frontend/
pip3 install -r requirements.txt
streamlit run ui/app.py
```

Then open [http://localhost:8501](http://localhost:8501) in your browser.

> Set `ANTHROPIC_API_KEY` in your environment to enable Claude reasoning in Agents 4, 10, and the Orchestrator. ARIA works fully without it using deterministic fallbacks.

### Evaluation & Tests

```bash
cd backend/
python3 evaluate.py   # Recall@N + MRR proof (< 60 seconds)
python3 test_aria.py  # Full test suite — all agents + pipeline
```

---

## Data Sources ($0 cost — all public)

| Source | Records | Agent | URL |
|--------|---------|-------|-----|
| NVD | 341,584 CVEs | 1 — CVE Ingestion | nvd.nist.gov |
| EPSS | 323,901 scores | 2 — Exploit Intel | first.org/epss |
| CISA KEV | 1,555 exploited | 2 — Exploit Intel | cisa.gov/kev |
| MITRE ATT&CK | 835 techniques | 3 — Threat Context | attack.mitre.org |
| GitHub Advisories | 500 advisories | 8 — Patch Feasibility | github.com/advisories |
| Microsoft MSRC | 2,179 CVEs | 8 — Patch Feasibility | msrc.microsoft.com |
| HHS Breach Portal | 697 breaches | Validation | hhs.gov/hipaa/breach |
| Asset Inventory | 56 assets (incl. database tier) | 5 — Asset Matching | Synthetic |
| Dependency Graph | 16 services | 7 — Blast Radius | Synthetic |

All data pre-downloaded to `data/raw/`. Do not re-download.

---

## Output Files

Every run produces three files in `output/`:

| File | Format | Audience |
|------|--------|----------|
| `aria_report_TIMESTAMP.md` | Markdown | Security team + management |
| `aria_audit_TIMESTAMP.json` | JSON | Compliance audit trail |
| `aria_ranked_TIMESTAMP.csv` | CSV | Spreadsheet / JIRA import |

### Report Sections

1. **Executive Summary** — 5-bullet CFO brief (breach risk $, fine exposure $, ROI $)
2. **Tier 1 (24h)** — Patch immediately, full action column, KEV/RW flags, confidence
3. **Tier 2 (7 days)** — Patch this sprint
4. **Maintenance Window Schedule** — Which CVEs in which window, engineer-hours, ROI per window
5. **Top 10 Full Analysis** — Per-CVE: ARIA score, confidence level, blast radius, compliance, Claude reasoning
6. **Tier 3/4** — Sprint backlog and monitor list

---

## Key Features

### 1. Maintenance Window Scheduling
> Directly addresses: "operational constraints such as maintenance windows and limited IT resources"

ARIA produces a concrete patch schedule:
- **Emergency window** — KEV/ransomware CVEs patched within hours, not days
- **Primary window** — Sunday 02:00–06:00 (8 engineer-hours)
- **Patch Tuesday window** — Tuesday 20:00–22:00 (2 hours, Microsoft patches)
- **Extended window** — Monthly (24 engineer-hours, complex patches)

Budget enforcement: if a window is full, CVEs queue to the next window or backlog.

### 2. Confidence Scores on Every CVE
Every output includes: `VERY HIGH / HIGH / MEDIUM / LOW`
- **VERY HIGH** — KEV confirmed + CPE exact asset match
- **HIGH** — Confirmed exploitation OR strong EPSS + verified asset
- **MEDIUM** — Moderate EPSS or keyword-based asset match
- **LOW** — Low EPSS, no asset match (CVSS-only signal)

### 3. Blast Radius — Three-Layer Fallback (No CVE Left at Zero)
ARIA uses three methods in order, taking the highest credible estimate:
- **Layer 1 — Graph BFS**: Walk the 16-node service dependency graph downstream from the matched asset
- **Layer 2 — Software Spread**: Count every other asset in the inventory running the same vulnerable software (correct model for library CVEs like log4j, openssl, nginx that hit every machine simultaneously)
- **Layer 3 — CWE + Criticality Heuristic**: When neither graph nor spread produces a count, estimate from the weakness category and asset properties

CVE-2024-47533 on `keycloak-identity-prod-56` scores blast=0.60 (CRITICAL) because 34 systems depend on the identity provider. CVE-2024-52304 on `api-gateway-prod-08` scores blast=0.54 because 15 downstream services inherit the risk. No other tool does this automatically.

### 4. Dollar-Denominated Prioritization
Every CVE: patch cost ($75/hr × hours), breach risk prevented ($), net ROI ($), fine exposure ($). Sorted by business impact, not technical severity.

### 5. Full Audit Trail
Every ranking decision is traceable. JSON audit trail records every signal value for every CVE. Judges/regulators can verify any recommendation.

---

## Reproducibility

```bash
# Full reproduction in 3 commands (run from backend/):
pip3 install -r requirements.txt
python3 test_aria.py     # verify all components work (56/56 pass)
python3 evaluate.py      # reproduce Recall@10=100% proof
```

If `ANTHROPIC_API_KEY` is set, Claude reasoning activates for Agents 4, 10, and the Orchestrator.
Without it, all three fall back to deterministic rule-based logic. **ARIA works fully without Claude.**

---

## Project Structure

```
UMD-Agentic-AI/
├── backend/                     # ARIA agent pipeline + API server
│   ├── api.py                   # FastAPI server  (POST /run)
│   ├── run_aria.py              # CLI entry point
│   ├── evaluate.py              # Back-test evaluation (Recall@N, MRR)
│   ├── test_aria.py             # Comprehensive test suite
│   ├── requirements.txt         # Backend Python dependencies
│   ├── agents/
│   │   ├── orchestrator.py      # Pipeline coordinator + Claude triage
│   │   ├── agent_01_ingest.py   # CVE ingestion (NVD)
│   │   ├── agent_02_exploit.py  # EPSS + CISA KEV exploit intelligence
│   │   ├── agent_03_threat.py   # MITRE ATT&CK tactic mapping
│   │   ├── agent_04_business.py # Business context parsing (Claude Haiku)
│   │   ├── agent_05_assets.py   # Asset matching (CPE + vendor + package)
│   │   ├── agent_06_compliance.py # PCI DSS / HIPAA / SOC2 fine estimation
│   │   ├── agent_07_blast.py    # Blast radius — three-layer fallback
│   │   ├── agent_08_patch.py    # Patch feasibility (GitHub + MSRC)
│   │   ├── agent_09_roi.py      # ROI calculation + confidence scoring
│   │   ├── agent_10_report.py   # Report generation (Claude Sonnet)
│   │   └── shared/
│   │       ├── scoring.py       # Canonical ARIA scoring formula
│   │       ├── scheduler.py     # Maintenance window scheduler
│   │       └── data_loader.py   # Data access layer
│   ├── data/raw/                # All 9 datasets (pre-downloaded)
│   ├── analysis/                # EDA + chart generation
│   │   ├── dataset_analysis.py
│   │   └── charts/              # 15 pre-generated charts
│   ├── notebooks/               # ARIA_Data_Foundation.ipynb
│   └── output/                  # Generated reports (auto-created on run)
│
└── frontend/                    # Web UI
    ├── requirements.txt         # Frontend Python dependencies
    └── ui/
        └── app.py               # Streamlit war room dashboard
```

---

## Competition Information

**Challenge:** UMD Agentic AI Challenge 2026 — Software Vulnerability Prioritization
**Problem:** Design an Agentic AI system that reviews vulnerability reports, internal documentation, and dependency maps to prioritize software upgrades.
**Key Dates:** Submission April 15 | Demo April 24, 2026

**How ARIA addresses every judging criterion:**

| Criterion | ARIA's Answer |
|-----------|---------------|
| Timeline & Cost | MVP complete in 4 weeks. Operating cost < $3,000/year ($0 data + ~$2/run Claude API). Reproducible in 3 commands. |
| ROI / Outcomes | $299M breach risk identified. 100% Recall@10 vs 0% CVSS-only. ARIA costs $0.10/CVE vs $120 manual analyst triage. |
| Unintended Consequences | Agent 8 flags patch dependency conflicts before scheduling. Confidence scores (VERY HIGH/HIGH/MEDIUM/LOW) on every CVE prevent over-patching low-signal findings. Maintenance window budget caps prevent engineer burnout. "System recommends, humans decide" — ARIA never auto-applies patches. |
| System Dependencies | Blast radius via 3-layer BFS on 16-node dependency graph. Maintenance window scheduling with engineer-hour budget enforcement. Downstream service impact quantified per CVE. |

---

*ARIA — Autonomous Risk Intelligence Agent · UMD Agentic AI Challenge 2026*
*System recommends, humans decide.*
