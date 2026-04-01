"""
ARIA Dataset Analysis
Full exploratory analysis of all data sources used in the ARIA system.
Generates charts and summary statistics for the April 15 submission deck.
"""

import json
import os
import warnings
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
import numpy as np
import pandas as pd
import seaborn as sns

warnings.filterwarnings('ignore')

# ── Paths ────────────────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW  = os.path.join(BASE, "data", "raw")
OUT  = os.path.join(BASE, "analysis", "charts")
os.makedirs(OUT, exist_ok=True)

# ── Style ─────────────────────────────────────────────────────────────────────
PALETTE  = ["#E63946", "#457B9D", "#1D3557", "#F4A261", "#2A9D8F", "#E9C46A", "#264653"]
ACCENT   = "#E63946"
BG       = "#F8F9FA"
DARK     = "#1D3557"

plt.rcParams.update({
    "figure.facecolor": BG,
    "axes.facecolor":   BG,
    "axes.edgecolor":   DARK,
    "axes.labelcolor":  DARK,
    "text.color":       DARK,
    "xtick.color":      DARK,
    "ytick.color":      DARK,
    "font.family":      "DejaVu Sans",
    "axes.spines.top":  False,
    "axes.spines.right":False,
    "axes.grid":        True,
    "grid.alpha":       0.3,
    "grid.color":       "#CCCCCC",
})

def save(name):
    path = os.path.join(OUT, name)
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved → {name}")


# ═══════════════════════════════════════════════════════════════════
# 1. NVD — NATIONAL VULNERABILITY DATABASE
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 1. NVD ANALYSIS ━━━")

with open(os.path.join(RAW, "nvd_2024.json")) as f:
    nvd_raw = json.load(f)

rows = []
for item in nvd_raw["vulnerabilities"]:
    cve = item["cve"]
    metrics = cve.get("metrics", {})

    # CVSS score — prefer v3.1 then v3.0 then v2
    score, severity, vector = None, "UNKNOWN", ""
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            d = m.get("cvssData", {})
            score    = d.get("baseScore")
            severity = d.get("baseSeverity") or m.get("baseSeverity", "UNKNOWN")
            vector   = d.get("vectorString", "")
            break

    cwes = [w["value"] for w in cve.get("weaknesses", []) for w in w.get("description", [])]
    cwe  = cwes[0] if cwes else "UNKNOWN"

    rows.append({
        "cve_id":    cve["id"],
        "published": cve.get("published", ""),
        "modified":  cve.get("lastModified", ""),
        "cvss":      score,
        "severity":  severity.upper() if severity else "UNKNOWN",
        "cwe":       cwe,
        "vector":    vector,
        "desc_len":  len(cve.get("descriptions", [{}])[0].get("value", "")),
    })

nvd = pd.DataFrame(rows)
nvd["published"] = pd.to_datetime(nvd["published"], errors="coerce")
nvd["month"]     = nvd["published"].dt.to_period("M")

print(f"  Records: {len(nvd):,}")
print(f"  Total in NVD DB: {nvd_raw['totalResults']:,}")
print(f"  CVSS coverage: {nvd['cvss'].notna().sum()} / {len(nvd)}")
print(f"  Severity dist:\n{nvd['severity'].value_counts().to_string()}")

# ── Chart 1a: Severity Distribution (donut) ──────────────────────────────────
sev_order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
sev_colors = {"CRITICAL": "#E63946", "HIGH": "#F4A261",
              "MEDIUM": "#E9C46A", "LOW": "#2A9D8F", "UNKNOWN": "#ADB5BD"}

sev_counts = nvd["severity"].value_counts().reindex(sev_order, fill_value=0)
labels = [f"{s}\n({sev_counts[s]})" for s in sev_order if sev_counts[s] > 0]
sizes  = [sev_counts[s] for s in sev_order if sev_counts[s] > 0]
colors = [sev_colors[s] for s in sev_order if sev_counts[s] > 0]

fig, ax = plt.subplots(figsize=(7, 7))
wedges, texts, autotexts = ax.pie(
    sizes, labels=labels, colors=colors,
    autopct="%1.1f%%", pctdistance=0.8,
    wedgeprops=dict(width=0.5), startangle=90
)
for at in autotexts:
    at.set_fontsize(10); at.set_fontweight("bold"); at.set_color("white")
ax.set_title("NVD — CVE Severity Distribution\n(Sample: 500 CVEs | Total DB: 341,584)",
             fontsize=14, fontweight="bold", pad=20, color=DARK)
fig.patch.set_facecolor(BG)
save("01_nvd_severity_donut.png")

# ── Chart 1b: CVSS Score Distribution (histogram) ───────────────────────────
fig, ax = plt.subplots(figsize=(10, 5))
cvss_data = nvd["cvss"].dropna()
ax.hist(cvss_data, bins=20, color=ACCENT, edgecolor="white", alpha=0.85)
ax.axvline(cvss_data.mean(), color=DARK, lw=2, linestyle="--",
           label=f"Mean: {cvss_data.mean():.1f}")
ax.axvline(7.0, color="#F4A261", lw=2, linestyle=":", label="High threshold (7.0)")
ax.axvline(9.0, color="#E63946", lw=2, linestyle=":", label="Critical threshold (9.0)")
ax.set_xlabel("CVSS Base Score", fontsize=12)
ax.set_ylabel("Number of CVEs", fontsize=12)
ax.set_title("NVD — CVSS Score Distribution\nWhy CVSS alone is insufficient for prioritization",
             fontsize=13, fontweight="bold", color=DARK)
ax.legend(fontsize=10)
ax.annotate("Most CVEs cluster\nbetween 5-9:\ncannot distinguish\nwhich to patch first",
            xy=(7.2, ax.get_ylim()[1]*0.6), fontsize=9, color=DARK,
            bbox=dict(boxstyle="round,pad=0.4", facecolor="#FFE8A3", alpha=0.8))
save("02_nvd_cvss_histogram.png")

# ── Chart 1c: Top CWE categories ─────────────────────────────────────────────
cwe_counts = nvd["cwe"].value_counts().head(10)
fig, ax = plt.subplots(figsize=(11, 5))
bars = ax.barh(range(len(cwe_counts)), cwe_counts.values,
               color=[PALETTE[i % len(PALETTE)] for i in range(len(cwe_counts))],
               edgecolor="white")
ax.set_yticks(range(len(cwe_counts)))
ax.set_yticklabels(cwe_counts.index, fontsize=10)
ax.set_xlabel("Number of CVEs", fontsize=11)
ax.set_title("NVD — Top 10 CWE Weakness Categories\nUnderstanding vulnerability root causes",
             fontsize=13, fontweight="bold", color=DARK)
for bar, val in zip(bars, cwe_counts.values):
    ax.text(val + 0.5, bar.get_y() + bar.get_height()/2,
            str(val), va="center", fontsize=9, color=DARK)
save("03_nvd_top_cwe.png")

print("  NVD charts done.")


# ═══════════════════════════════════════════════════════════════════
# 2. EPSS — EXPLOIT PREDICTION SCORING SYSTEM
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 2. EPSS ANALYSIS ━━━")

with open(os.path.join(RAW, "epss_full.json")) as f:
    epss_raw = json.load(f)

epss = pd.DataFrame(epss_raw["data"])
epss["epss"]       = epss["epss"].astype(float)
epss["percentile"] = epss["percentile"].astype(float)

print(f"  Records: {len(epss):,} (Total in EPSS DB: {epss_raw['total']:,})")
print(f"  EPSS score range: {epss['epss'].min():.4f} – {epss['epss'].max():.4f}")
print(f"  Mean EPSS: {epss['epss'].mean():.4f}")
print(f"  CVEs with EPSS > 0.1: {(epss['epss'] > 0.1).sum()}")
print(f"  CVEs with EPSS > 0.5: {(epss['epss'] > 0.5).sum()}")

# ── Chart 2a: EPSS distribution ──────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(13, 5))

# Left: log-scale distribution
axes[0].hist(epss["epss"], bins=50, color="#457B9D", edgecolor="white", alpha=0.85)
axes[0].set_yscale("log")
axes[0].set_xlabel("EPSS Score", fontsize=11)
axes[0].set_ylabel("Number of CVEs (log scale)", fontsize=11)
axes[0].set_title("EPSS Score Distribution\n(log scale — most CVEs near zero)", fontsize=12, fontweight="bold")
axes[0].axvline(0.1, color=ACCENT, lw=2, linestyle="--", label="0.1 threshold")
axes[0].legend()

# Right: Cumulative
sorted_epss = np.sort(epss["epss"].values)
cdf = np.arange(1, len(sorted_epss)+1) / len(sorted_epss)
axes[1].plot(sorted_epss, cdf, color="#457B9D", lw=2)
axes[1].axvline(0.1, color=ACCENT, lw=2, linestyle="--", label="EPSS = 0.1")
axes[1].axhline(cdf[np.searchsorted(sorted_epss, 0.1)],
                color="#F4A261", lw=1.5, linestyle=":", label="CDF at 0.1")
axes[1].set_xlabel("EPSS Score", fontsize=11)
axes[1].set_ylabel("Cumulative Fraction of CVEs", fontsize=11)
axes[1].set_title("EPSS Cumulative Distribution\n95%+ CVEs have EPSS < 0.1", fontsize=12, fontweight="bold")
axes[1].legend(fontsize=9)

pct_below_01 = (epss["epss"] < 0.1).mean() * 100
axes[1].annotate(f"{pct_below_01:.1f}% of CVEs\nhave EPSS < 0.1",
                 xy=(0.05, 0.5), fontsize=9, color=DARK,
                 bbox=dict(boxstyle="round", facecolor="#E8F4F8", alpha=0.8))

fig.suptitle("EPSS — Why CVSS Alone Misses the Point\nHigh CVSS ≠ High Exploit Probability",
             fontsize=14, fontweight="bold", color=DARK, y=1.02)
plt.tight_layout()
save("04_epss_distribution.png")

# ── Chart 2b: CVSS vs EPSS scatter (using NVD-EPSS merge) ───────────────────
nvd_epss = pd.merge(nvd[["cve_id","cvss","severity"]], epss[["cve","epss"]],
                    left_on="cve_id", right_on="cve", how="inner")

print(f"  NVD-EPSS overlap: {len(nvd_epss)} CVEs")

if len(nvd_epss) > 0:
    fig, ax = plt.subplots(figsize=(10, 6))
    sev_c = {"CRITICAL":"#E63946","HIGH":"#F4A261","MEDIUM":"#E9C46A",
              "LOW":"#2A9D8F","UNKNOWN":"#ADB5BD"}
    for sev, grp in nvd_epss.groupby("severity"):
        ax.scatter(grp["cvss"], grp["epss"], c=sev_c.get(sev,"#ADB5BD"),
                   alpha=0.6, s=40, label=sev, edgecolors="none")

    ax.axvline(9.0, color="#E63946", lw=1.5, linestyle="--", alpha=0.6, label="CVSS Critical (9.0)")
    ax.axhline(0.1, color="#457B9D", lw=1.5, linestyle="--", alpha=0.6, label="EPSS threshold (0.1)")

    # Annotate quadrants
    ax.text(9.5, 0.6, "PATCH\nIMMEDIATELY", fontsize=9, color="#E63946",
            fontweight="bold", ha="center",
            bbox=dict(boxstyle="round", facecolor="#FFE0E0", alpha=0.7))
    ax.text(9.5, 0.01, "Low real-world\nrisk despite\nhigh CVSS", fontsize=8,
            color="#666", ha="center",
            bbox=dict(boxstyle="round", facecolor="#F0F0F0", alpha=0.7))
    ax.text(2.5, 0.6, "Active exploit,\nlow CVSS —\noften MISSED", fontsize=8,
            color="#E63946", ha="center",
            bbox=dict(boxstyle="round", facecolor="#FFE8A3", alpha=0.7))

    ax.set_xlabel("CVSS Base Score", fontsize=12)
    ax.set_ylabel("EPSS Score (Exploit Probability)", fontsize=12)
    ax.set_title("CVSS vs EPSS — The Prioritization Gap\nHigh CVSS ≠ High Exploit Risk",
                 fontsize=13, fontweight="bold", color=DARK)
    ax.legend(title="Severity", fontsize=9, loc="upper left")
    save("05_cvss_vs_epss_scatter.png")


# ═══════════════════════════════════════════════════════════════════
# 3. CISA KEV — KNOWN EXPLOITED VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 3. CISA KEV ANALYSIS ━━━")

with open(os.path.join(RAW, "cisa_kev.json")) as f:
    kev_raw = json.load(f)

kev = pd.DataFrame(kev_raw["vulnerabilities"])
kev["dateAdded"]          = pd.to_datetime(kev["dateAdded"], errors="coerce")
kev["dueDate"]            = pd.to_datetime(kev["dueDate"], errors="coerce")
kev["year"]               = kev["dateAdded"].dt.year
kev["days_to_remediate"]  = (kev["dueDate"] - kev["dateAdded"]).dt.days

print(f"  Records: {len(kev):,}")
print(f"  Date range: {kev['dateAdded'].min().date()} → {kev['dateAdded'].max().date()}")
print(f"  Unique vendors: {kev['vendorProject'].nunique()}")
print(f"  Top vendors:\n{kev['vendorProject'].value_counts().head(5).to_string()}")

# ── Chart 3a: KEV entries over time ─────────────────────────────────────────
kev_by_year = kev["year"].value_counts().sort_index()
kev_by_year = kev_by_year[kev_by_year.index >= 2021]

fig, ax = plt.subplots(figsize=(10, 5))
bars = ax.bar(kev_by_year.index.astype(str), kev_by_year.values,
              color=PALETTE[:len(kev_by_year)], edgecolor="white", width=0.6)
for bar, val in zip(bars, kev_by_year.values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
            str(val), ha="center", fontsize=11, fontweight="bold", color=DARK)
ax.set_xlabel("Year", fontsize=12)
ax.set_ylabel("CVEs Added to CISA KEV", fontsize=12)
ax.set_title(f"CISA KEV — Known Exploited Vulnerabilities Over Time\nTotal: {len(kev):,} actively exploited CVEs",
             fontsize=13, fontweight="bold", color=DARK)
save("06_kev_by_year.png")

# ── Chart 3b: Top vendors in KEV ────────────────────────────────────────────
top_vendors = kev["vendorProject"].value_counts().head(12)
fig, ax = plt.subplots(figsize=(11, 5))
bars = ax.barh(range(len(top_vendors)), top_vendors.values,
               color=[PALETTE[i % len(PALETTE)] for i in range(len(top_vendors))],
               edgecolor="white")
ax.set_yticks(range(len(top_vendors)))
ax.set_yticklabels(top_vendors.index, fontsize=10)
ax.set_xlabel("Number of Exploited CVEs", fontsize=11)
ax.set_title("CISA KEV — Most Exploited Vendors\nCritical for Asset-to-CVE Matching",
             fontsize=13, fontweight="bold", color=DARK)
for bar, val in zip(bars, top_vendors.values):
    ax.text(val + 0.3, bar.get_y() + bar.get_height()/2,
            str(val), va="center", fontsize=9, color=DARK)
save("07_kev_top_vendors.png")

# ── Chart 3c: Days to remediate distribution ─────────────────────────────────
days = kev["days_to_remediate"].dropna()
days = days[(days > 0) & (days < 200)]

fig, ax = plt.subplots(figsize=(10, 5))
ax.hist(days, bins=30, color="#2A9D8F", edgecolor="white", alpha=0.85)
ax.axvline(days.median(), color=ACCENT, lw=2, linestyle="--",
           label=f"Median: {days.median():.0f} days")
ax.axvline(14, color="#F4A261", lw=2, linestyle=":",
           label="14-day common deadline")
ax.set_xlabel("Days to Remediation Deadline", fontsize=12)
ax.set_ylabel("Number of CVEs", fontsize=12)
ax.set_title("CISA KEV — Mandated Remediation Timelines\nFederal agencies must patch within these windows",
             fontsize=13, fontweight="bold", color=DARK)
ax.legend(fontsize=10)
save("08_kev_remediation_days.png")

print(f"  KEV charts done. Median remediation: {days.median():.0f} days")


# ═══════════════════════════════════════════════════════════════════
# 4. EPSS  ×  KEV — THE CORE INSIGHT
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 4. EPSS × KEV INSIGHT CHART ━━━")

# Merge EPSS with KEV
kev_ids = set(kev["cveID"].str.upper())
epss["in_kev"] = epss["cve"].str.upper().isin(kev_ids)

kev_epss     = epss[epss["in_kev"]]["epss"]
non_kev_epss = epss[~epss["in_kev"]]["epss"]

fig, ax = plt.subplots(figsize=(10, 5))
ax.hist(non_kev_epss, bins=40, alpha=0.7, color="#457B9D", label=f"Not in KEV (n={len(non_kev_epss):,})", density=True)
ax.hist(kev_epss,     bins=40, alpha=0.8, color="#E63946", label=f"In CISA KEV (n={len(kev_epss):,})", density=True)
ax.set_xlabel("EPSS Score", fontsize=12)
ax.set_ylabel("Density", fontsize=12)
ax.set_title("EPSS Distribution: KEV vs Non-KEV CVEs\nCISA-confirmed exploits have dramatically higher EPSS scores",
             fontsize=13, fontweight="bold", color=DARK)
ax.legend(fontsize=11)
ax.annotate(f"KEV median EPSS: {kev_epss.median():.3f}\nNon-KEV median: {non_kev_epss.median():.4f}",
            xy=(0.5, ax.get_ylim()[1]*0.6), fontsize=10, color=DARK,
            bbox=dict(boxstyle="round", facecolor="#FFE8A3", alpha=0.85))
save("09_epss_vs_kev.png")
print(f"  KEV median EPSS: {kev_epss.median():.3f} vs non-KEV: {non_kev_epss.median():.4f}")


# ═══════════════════════════════════════════════════════════════════
# 5. GITHUB SECURITY ADVISORIES
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 5. GITHUB ADVISORIES ANALYSIS ━━━")

with open(os.path.join(RAW, "github_advisories_full.json")) as f:
    gh_raw = json.load(f)

gh_rows = []
for a in gh_raw:
    gh_rows.append({
        "ghsa_id":   a.get("ghsa_id", ""),
        "severity":  a.get("severity", "UNKNOWN").upper(),
        "published": a.get("published_at", ""),
        "updated":   a.get("updated_at", ""),
        "cve_id":    a.get("cve_id", ""),
        "ecosystem": a.get("vulnerabilities", [{}])[0].get("package", {}).get("ecosystem", "UNKNOWN") if a.get("vulnerabilities") else "UNKNOWN",
        "has_patch": any(v.get("patched_versions") for v in a.get("vulnerabilities", [])),
        "n_vulns":   len(a.get("vulnerabilities", [])),
    })

gh = pd.DataFrame(gh_rows)
gh["published"] = pd.to_datetime(gh["published"], errors="coerce")
gh["has_cve"]   = gh["cve_id"].notna() & (gh["cve_id"] != "")

print(f"  Records: {len(gh):,}")
print(f"  With CVE ID: {gh['has_cve'].sum()}")
print(f"  With patch: {gh['has_patch'].sum()}")
print(f"  Ecosystems:\n{gh['ecosystem'].value_counts().head(8).to_string()}")

# ── Chart 5a: Ecosystem breakdown ───────────────────────────────────────────
eco_counts = gh["ecosystem"].value_counts().head(10)
fig, axes = plt.subplots(1, 2, figsize=(13, 5))

axes[0].bar(eco_counts.index, eco_counts.values,
            color=[PALETTE[i % len(PALETTE)] for i in range(len(eco_counts))],
            edgecolor="white")
axes[0].set_xticklabels(eco_counts.index, rotation=35, ha="right", fontsize=9)
axes[0].set_title("Advisories by Package Ecosystem", fontsize=12, fontweight="bold")
axes[0].set_ylabel("Number of Advisories", fontsize=11)

# Patch availability by severity
patch_sev = gh.groupby("severity")["has_patch"].agg(["sum", "count"])
patch_sev["pct"] = patch_sev["sum"] / patch_sev["count"] * 100
patch_sev = patch_sev[patch_sev["count"] > 2].sort_values("pct", ascending=False)

colors_sev = [sev_colors.get(s, "#ADB5BD") for s in patch_sev.index]
axes[1].bar(patch_sev.index, patch_sev["pct"], color=colors_sev, edgecolor="white")
axes[1].set_ylabel("% with Patch Available", fontsize=11)
axes[1].set_title("Patch Availability by Severity\n(Higher severity = more urgency when patch exists)",
                  fontsize=12, fontweight="bold")
for i, (idx, row) in enumerate(patch_sev.iterrows()):
    axes[1].text(i, row["pct"] + 1, f"{row['pct']:.0f}%",
                 ha="center", fontsize=10, fontweight="bold", color=DARK)

fig.suptitle("GitHub Security Advisories — Patch Feasibility Data",
             fontsize=14, fontweight="bold", color=DARK)
plt.tight_layout()
save("10_github_advisories.png")


# ═══════════════════════════════════════════════════════════════════
# 6. MITRE ATT&CK
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 6. MITRE ATT&CK ANALYSIS ━━━")

with open(os.path.join(RAW, "mitre_techniques.json")) as f:
    att_raw = json.load(f)

att = pd.DataFrame(att_raw)
att = att[~att["deprecated"].fillna(False)]
att_exploded = att.explode("tactics")
tactic_counts = att_exploded["tactics"].value_counts()
platform_all  = [p for pl in att["platforms"].dropna() for p in pl]
plat_counts   = Counter(platform_all)

print(f"  Techniques (active): {len(att):,}")
print(f"  Subtechniques: {att['is_subtechnique'].sum()}")
print(f"  Top tactics:\n{tactic_counts.head(5).to_string()}")

# ── Chart 6: Tactic landscape ────────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(14, 6))

# Tactic bar chart
tc_sorted = tactic_counts.head(10).sort_values()
axes[0].barh(tc_sorted.index, tc_sorted.values,
             color=[PALETTE[i % len(PALETTE)] for i in range(len(tc_sorted))],
             edgecolor="white")
axes[0].set_title("ATT&CK Techniques by Tactic\n(What ARIA maps CVEs to)",
                  fontsize=12, fontweight="bold")
axes[0].set_xlabel("Number of Techniques", fontsize=11)

# Platform bar chart
top_plat = dict(sorted(plat_counts.items(), key=lambda x: x[1], reverse=True)[:8])
axes[1].bar(top_plat.keys(), top_plat.values(),
            color=[PALETTE[i % len(PALETTE)] for i in range(len(top_plat))],
            edgecolor="white")
axes[1].set_xticklabels(top_plat.keys(), rotation=30, ha="right", fontsize=9)
axes[1].set_title("ATT&CK Techniques by Target Platform\n(Maps CVEs to affected technology stacks)",
                  fontsize=12, fontweight="bold")
axes[1].set_ylabel("Technique Count", fontsize=11)

fig.suptitle("MITRE ATT&CK — Threat Intelligence Layer\nConnects CVEs to real attack patterns & threat actors",
             fontsize=13, fontweight="bold", color=DARK)
plt.tight_layout()
save("11_mitre_attack.png")


# ═══════════════════════════════════════════════════════════════════
# 7. ASSET INVENTORY ANALYSIS
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 7. ASSET INVENTORY ANALYSIS ━━━")

with open(os.path.join(RAW, "asset_inventory.json")) as f:
    assets = json.load(f)

ast = pd.DataFrame(assets)
print(f"  Assets: {len(ast)}")
print(f"  Internet-facing: {ast['internet_facing'].sum()}")
print(f"  Critical: {(ast['criticality']=='critical').sum()}")
print(f"  PCI DSS scope: {ast['pci_dss_scope'].sum()}")

fig, axes = plt.subplots(2, 2, figsize=(13, 10))

# Business unit breakdown
bu_counts = ast["business_unit"].value_counts()
axes[0,0].pie(bu_counts.values, labels=bu_counts.index, colors=PALETTE,
              autopct="%1.0f%%", pctdistance=0.8,
              wedgeprops=dict(width=0.5))
axes[0,0].set_title("Assets by Business Unit", fontsize=12, fontweight="bold")

# Criticality
crit_counts = ast["criticality"].value_counts()
crit_colors_map = {"critical":"#E63946","high":"#F4A261","medium":"#E9C46A","low":"#2A9D8F"}
axes[0,1].bar(crit_counts.index, crit_counts.values,
              color=[crit_colors_map.get(c,"#ADB5BD") for c in crit_counts.index],
              edgecolor="white")
axes[0,1].set_title("Asset Criticality Levels", fontsize=12, fontweight="bold")
axes[0,1].set_ylabel("Count", fontsize=11)

# Internet-facing by BU
facing_bu = ast.groupby("business_unit")["internet_facing"].agg(["sum","count"])
facing_bu["pct"] = facing_bu["sum"] / facing_bu["count"] * 100
facing_bu = facing_bu.sort_values("pct", ascending=False)
axes[1,0].barh(facing_bu.index, facing_bu["pct"],
               color=[ACCENT if p == 100 else "#457B9D" for p in facing_bu["pct"]],
               edgecolor="white")
axes[1,0].set_title("% Internet-Facing by Business Unit\n(Higher = higher attack surface)",
                    fontsize=11, fontweight="bold")
axes[1,0].set_xlabel("% Internet-Facing", fontsize=10)

# Compliance scope
comp = {
    "PCI DSS": ast["pci_dss_scope"].sum(),
    "SOC2":    ast["soc2_scope"].sum(),
    "HIPAA":   ast["hipaa_scope"].sum(),
    "None":    ((~ast["pci_dss_scope"]) & (~ast["soc2_scope"]) & (~ast["hipaa_scope"])).sum()
}
axes[1,1].bar(comp.keys(), comp.values(),
              color=[PALETTE[i] for i in range(len(comp))], edgecolor="white")
axes[1,1].set_title("Assets in Compliance Scope\n(Drives fine estimation in ARIA)",
                    fontsize=11, fontweight="bold")
axes[1,1].set_ylabel("Number of Assets", fontsize=10)

fig.suptitle("Synthetic Asset Inventory — Business Context Layer\n(In production: replaced by CMDB / ServiceNow data)",
             fontsize=13, fontweight="bold", color=DARK)
plt.tight_layout()
save("12_asset_inventory.png")


# ═══════════════════════════════════════════════════════════════════
# 8. MULTI-SOURCE COMPARISON — THE ARIA ADVANTAGE
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 8. ARIA MULTI-SOURCE ADVANTAGE CHART ━━━")

# Show what each source adds on top of CVSS
fig, ax = plt.subplots(figsize=(12, 7))
ax.set_xlim(0, 10); ax.set_ylim(-0.5, 5.5)
ax.axis("off")

layers = [
    ("NVD / CVSS Score", "#ADB5BD",
     "Base technical severity — the industry standard starting point\n"
     "341,584 CVEs | Scores 0–10 | Tells you: How severe technically?"),
    ("+ EPSS Score", "#457B9D",
     "Real-world exploit probability — adds urgency signal\n"
     "323,901 CVEs | 95%+ have EPSS < 0.1 | Tells you: Is anyone exploiting this?"),
    ("+ CISA KEV", "#2A9D8F",
     "Confirmed active exploitation — mandatory escalation trigger\n"
     "1,555 CVEs | Federal mandate | Tells you: Is it exploited RIGHT NOW?"),
    ("+ Asset Inventory", "#F4A261",
     "Business context — filters to your environment only\n"
     "Your assets | Software versions | Tells you: Are YOU affected?"),
    ("+ Compliance + Blast Radius + ATT&CK", "#E63946",
     "Business impact — the ARIA layer no other tool has\n"
     "Dollar risk | Regulatory fines | Attack paths | Tells you: What does it COST your business?"),
]

for i, (label, color, desc) in enumerate(layers):
    y = 4.8 - i * 1.0
    ax.add_patch(mpatches.FancyBboxPatch((0.1, y-0.35), 9.8, 0.75,
                                          boxstyle="round,pad=0.05",
                                          facecolor=color, alpha=0.85, edgecolor="white", lw=2))
    ax.text(0.35, y, label, fontsize=11, fontweight="bold", color="white", va="center")
    ax.text(5.5,  y, desc,  fontsize=8.5, color="white", va="center")

ax.text(5, -0.2,
        "ARIA combines all five layers autonomously. Existing tools stop at layer 2 or 3.",
        ha="center", fontsize=10, color=DARK, style="italic",
        bbox=dict(boxstyle="round", facecolor="#FFE8A3", alpha=0.9))
ax.set_title("ARIA Signal Stack — Why Multi-Source Reasoning Wins\nEach layer adds what the previous one misses",
             fontsize=14, fontweight="bold", color=DARK, pad=15)
save("13_aria_signal_stack.png")


# ═══════════════════════════════════════════════════════════════════
# 9. DATASET COVERAGE SUMMARY CARD
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ 9. DATASET SUMMARY CARD ━━━")

summary = {
    "NVD":              {"records": f"341,584 total\n(500 sampled)", "agent": "CVE Ingestion",       "cost": "Free"},
    "EPSS":             {"records": f"323,901 CVEs",                 "agent": "Exploit Intelligence", "cost": "Free"},
    "CISA KEV":         {"records": f"1,555 CVEs",                   "agent": "Exploit Intelligence", "cost": "Free"},
    "MITRE ATT&CK":     {"records": f"835 techniques",               "agent": "Threat Context",       "cost": "Free"},
    "GitHub Advisories":{"records": f"500 sampled",                  "agent": "Patch Feasibility",    "cost": "Free"},
    "Asset Inventory":  {"records": f"50 assets (synthetic)",         "agent": "Asset Matching",       "cost": "Free"},
    "Dependency Graph": {"records": f"10 services, 10 packages",      "agent": "Blast Radius",         "cost": "Free"},
}

fig, ax = plt.subplots(figsize=(13, 6))
ax.axis("off")

headers = ["Data Source", "Records / Scale", "Primary Agent", "Cost"]
rows_data = [[src, v["records"], v["agent"], v["cost"]] for src, v in summary.items()]

tbl = ax.table(
    cellText=rows_data, colLabels=headers,
    cellLoc="center", loc="center",
    colWidths=[0.22, 0.28, 0.30, 0.10]
)
tbl.auto_set_font_size(False)
tbl.set_fontsize(10)
tbl.scale(1, 2.2)

for (row, col), cell in tbl.get_celld().items():
    cell.set_edgecolor("#CCCCCC")
    if row == 0:
        cell.set_facecolor(DARK); cell.set_text_props(color="white", fontweight="bold")
    elif row % 2 == 0:
        cell.set_facecolor("#EDF2F7")
    else:
        cell.set_facecolor("white")

ax.set_title("ARIA Data Sources — Complete Coverage Map\nAll sources publicly available, zero licensing cost",
             fontsize=13, fontweight="bold", color=DARK, pad=20)
save("14_dataset_summary_table.png")


# ═══════════════════════════════════════════════════════════════════
# 10. KEY STATISTICS SUMMARY
# ═══════════════════════════════════════════════════════════════════
print("\n━━━ FINAL SUMMARY STATS ━━━")

stats = {
    "NVD total CVEs in database": f"{nvd_raw['totalResults']:,}",
    "EPSS total CVEs scored":     f"{epss_raw['total']:,}",
    "CISA KEV actively exploited": f"{len(kev):,}",
    "MITRE ATT&CK techniques":    f"{len(att):,}",
    "GitHub advisories sampled":  f"{len(gh):,}",
    "Synthetic assets":           f"50",
    "NVD CVEs with CVSS > 9 (Critical)": f"{(nvd['cvss'] > 9).sum()}",
    "EPSS CVEs with score > 0.5": f"{(epss['epss'] > 0.5).sum():,}",
    "KEV: median days to patch":  f"{days.median():.0f} days",
    "NVD-EPSS CVEs overlapping":  f"{len(nvd_epss)}",
}

print("\n" + "="*55)
print("  ARIA DATASET STATISTICS")
print("="*55)
for k, v in stats.items():
    print(f"  {k:<42} {v}")
print("="*55)

# Save stats to JSON for report
with open(os.path.join(OUT, "summary_stats.json"), "w") as f:
    json.dump(stats, f, indent=2)

print(f"\n✓ All charts saved to: analysis/charts/")
print(f"  Total charts generated: 14")
