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
| **MRR** | **0.521** | 0.026 | 0.410 |
| **Avg rank of KEV CVEs** | **2** | 122 | 18 |

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

## Quick Start (5 minutes)

### 1. Install dependencies

```bash
pip install pandas anthropic requests matplotlib seaborn plotly kaleido
```

### 2. Run ARIA (demo mode — no API key needed)

```bash
python run_aria.py
```

Output appears in `output/` as `.md` (human report), `.json` (audit trail), `.csv` (spreadsheet).

### 3. Run ARIA on your organization

```bash
python run_aria.py --org "We are a healthcare SaaS company serving hospitals. \
  We store patient records (PHI), process credit card payments, and run on AWS. \
  Stack: Python, React, PostgreSQL, Docker. 500 employees."
```

### 4. Run the evaluation (reproduce our proof)

```bash
python evaluate.py
```

Prints Recall@N and MRR for ARIA, CVSS-only, and EPSS-only on the same 500 CVEs.

### 5. Run the full test suite

```bash
python test_aria.py
```

Tests every agent, the scoring formula, the scheduler, and the full pipeline.

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
| Asset Inventory | 50 assets | 5 — Asset Matching | Synthetic |
| Dependency Graph | 10 services | 7 — Blast Radius | Synthetic |

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

### 3. Blast Radius via Dependency Graph BFS
CVE-2024-52304 on `api-gateway-prod-08` scores blast=0.56 because 14 downstream services inherit the risk. Computed by BFS traversal of your service dependency graph — no other tool does this automatically.

### 4. Dollar-Denominated Prioritization
Every CVE: patch cost ($75/hr × hours), breach risk prevented ($), net ROI ($), fine exposure ($). Sorted by business impact, not technical severity.

### 5. Full Audit Trail
Every ranking decision is traceable. JSON audit trail records every signal value for every CVE. Judges/regulators can verify any recommendation.

---

## Reproducibility

```bash
# Full reproduction in 3 commands:
pip install pandas anthropic requests matplotlib seaborn plotly kaleido
python test_aria.py     # verify all components work
python evaluate.py      # reproduce Recall@10=100% proof
```

If `ANTHROPIC_API_KEY` is set, Claude reasoning activates for Agents 4, 10, and the Orchestrator.
Without it, all three fall back to deterministic rule-based logic. **ARIA works fully without Claude.**

---

## Project Structure

```
UMD-Agentic-AI/
├── run_aria.py              # Main entry point
├── evaluate.py              # Back-test evaluation (Recall@N, MRR)
├── test_aria.py             # Comprehensive test suite (unit + integration + eval)
├── agents/
│   ├── orchestrator.py      # Pipeline coordinator + Claude triage validation
│   ├── agent_01_ingest.py   # CVE ingestion (NVD)
│   ├── agent_02_exploit.py  # EPSS + CISA KEV exploit intelligence
│   ├── agent_03_threat.py   # MITRE ATT&CK tactic mapping
│   ├── agent_04_business.py # Business context parsing (Claude Haiku)
│   ├── agent_05_assets.py   # Asset matching (CPE + vendor + package)
│   ├── agent_06_compliance.py # PCI DSS / HIPAA / SOC2 fine estimation
│   ├── agent_07_blast.py    # Blast radius via BFS dependency traversal
│   ├── agent_08_patch.py    # Patch feasibility (GitHub + MSRC)
│   ├── agent_09_roi.py      # ROI calculation + confidence scoring
│   ├── agent_10_report.py   # Report generation (Claude Sonnet)
│   └── shared/
│       ├── scoring.py       # Canonical ARIA scoring formula + confidence
│       ├── scheduler.py     # Maintenance window scheduler
│       └── data_loader.py   # Data access layer
├── data/raw/                # All 9 datasets (pre-downloaded, do not re-download)
├── analysis/                # EDA + chart generation
│   ├── dataset_analysis.py
│   └── charts/              # 15 pre-generated charts
├── notebooks/               # ARIA_Data_Foundation.ipynb (data story)
└── output/                  # Generated reports (auto-created on run)
```

---

## Competition Information

**Challenge:** UMD Agentic AI Challenge 2026 — Software Vulnerability Prioritization
**Problem:** Design an Agentic AI system that reviews vulnerability reports, internal documentation, and dependency maps to prioritize software upgrades.
**Key Dates:** Submission April 15 | Demo April 24, 2026

**How ARIA addresses every judging criterion:**

| Criterion | ARIA's Answer |
|-----------|---------------|
| Timeline & Cost | MVP complete in 4 weeks. Operating cost < $3,000/year. $0 data cost. |
| ROI / Outcomes | $291M breach risk identified. 100% Recall@10 vs 0% CVSS-only. $34M analyst savings. |
| Risk Assessment | Full audit trail. Confidence scores on every CVE. Claude only at output layer — scoring is deterministic. |
| System Dependencies | Blast radius via BFS on dependency graph. Maintenance window scheduling with engineer-hour budget constraints. |

---

*ARIA — Autonomous Risk Intelligence Agent · UMD Agentic AI Challenge 2026*
*System recommends, humans decide.*
