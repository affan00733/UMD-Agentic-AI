# ARIA — Autonomous Risk Intelligence Agent
### UMD Agentic AI Challenge 2026

Multi-agent AI system for CVE patch prioritization using business context reasoning.

## Repository Structure

```
ARIA/
├── data/
│   ├── raw/                             # All downloaded datasets
│   │   ├── nvd_2024.json                # NVD CVE data (500 sampled, 341K in DB)
│   │   ├── epss_full.json               # EPSS exploit probability (10K CVEs)
│   │   ├── cisa_kev.json                # CISA Known Exploited Vulns (1,555)
│   │   ├── mitre_techniques.json        # MITRE ATT&CK techniques (835)
│   │   ├── github_advisories_full.json  # GitHub Security Advisories (500)
│   │   ├── msrc_full.json               # Microsoft MSRC patches 2024 (2,179)
│   │   ├── hhs_breach.csv               # HHS Breach Portal records (697)
│   │   ├── asset_inventory.json         # Synthetic asset inventory (50 assets)
│   │   └── dependency_graph.json        # Synthetic service dependency graph
│   └── processed/                       # Cleaned/merged datasets (generated)
│
├── analysis/
│   ├── dataset_analysis.py              # Full EDA — run to regenerate all charts
│   └── charts/                          # 15 generated visualization charts
│
├── notebooks/                           # Jupyter notebooks
└── agents/                              # ARIA agent system (in progress)
```

## Setup

```bash
pip install requests pandas matplotlib seaborn plotly kaleido
python analysis/dataset_analysis.py
```

## Data Sources

| Source | Records | Agent |
|--------|---------|-------|
| NVD | 341,584 CVEs total | CVE Ingestion |
| EPSS | 323,901 CVEs scored | Exploit Intelligence |
| CISA KEV | 1,555 actively exploited | Exploit Intelligence |
| MITRE ATT&CK | 835 techniques | Threat Context |
| GitHub Advisories | 500 advisories | Patch Feasibility |
| Microsoft MSRC | 2,179 CVEs (2024) | Patch Feasibility |
| HHS Breach Portal | 697 breach records | Validation / Back-test |
| Asset Inventory | 50 assets (synthetic) | Asset Matching |
| Dependency Graph | 10 services (synthetic) | Blast Radius |