"""
shared/data_loader.py
Loads all 7 ARIA data sources once at startup and exposes them as
clean pandas DataFrames and dicts. All agents import from here.
"""

import json, csv, os
import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW  = os.path.join(BASE, "data", "raw")

def _path(filename):
    return os.path.join(RAW, filename)

# ── NVD ───────────────────────────────────────────────────────────────────────
def load_nvd() -> pd.DataFrame:
    """Returns DataFrame with columns: cve_id, cvss, severity, cwe, published, year."""
    with open(_path("nvd_recent.json")) as f:
        raw = json.load(f)
    rows = []
    for item in raw["vulnerabilities"]:
        cve  = item["cve"]
        mets = cve.get("metrics", {})
        score, severity, cwe = None, "UNKNOWN", "UNKNOWN"
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]:
            if key in mets and mets[key]:
                m = mets[key][0]
                d = m.get("cvssData", {})
                score    = d.get("baseScore")
                severity = (d.get("baseSeverity") or m.get("baseSeverity", "UNKNOWN") or "UNKNOWN").upper()
                break
        for w in cve.get("weaknesses", []):
            for desc in w.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe = desc["value"]
                    break
            if cwe != "UNKNOWN":
                break
        # Collect affected product CPE strings
        affected = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        affected.append(match.get("criteria", ""))
        rows.append({
            "cve_id":    cve["id"],
            "published": cve.get("published", ""),
            "cvss":      score,
            "severity":  severity,
            "cwe":       cwe,
            "affected":  affected,           # list of CPE strings
            "description": next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            ),
        })
    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"], errors="coerce")
    df["year"]      = df["published"].dt.year
    df["cvss"]      = pd.to_numeric(df["cvss"], errors="coerce")
    return df

# ── EPSS ──────────────────────────────────────────────────────────────────────
def load_epss_full() -> pd.DataFrame:
    """10 000-CVE unbiased sample — use for distribution stats."""
    with open(_path("epss_full.json")) as f:
        raw = json.load(f)
    df = pd.DataFrame(raw["data"])
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    if "cve" in df.columns and "cve_id" not in df.columns:
        df = df.rename(columns={"cve": "cve_id"})
    return df

def load_epss_matched() -> pd.DataFrame:
    """2 051-CVE set matched to NVD 2024 + KEV — use for per-CVE scoring."""
    with open(_path("epss_matched.json")) as f:
        raw = json.load(f)
    df = pd.DataFrame(raw["data"])
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    if "cve" in df.columns and "cve_id" not in df.columns:
        df = df.rename(columns={"cve": "cve_id"})
    return df

# ── CISA KEV ──────────────────────────────────────────────────────────────────
def load_kev() -> pd.DataFrame:
    """Returns DataFrame with columns: cve_id, vendorProject, product,
    dateAdded, dueDate, days_to_remediate, ransomware (bool), shortDescription."""
    with open(_path("cisa_kev.json")) as f:
        raw = json.load(f)
    df = pd.DataFrame(raw["vulnerabilities"]).rename(columns={"cveID": "cve_id"})
    df["dateAdded"] = pd.to_datetime(df["dateAdded"], errors="coerce")
    df["dueDate"]   = pd.to_datetime(df["dueDate"],   errors="coerce")
    df["days_to_remediate"] = (df["dueDate"] - df["dateAdded"]).dt.days
    df["ransomware"] = df["knownRansomwareCampaignUse"].str.strip().str.lower() == "known"
    return df

# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────
def load_mitre() -> list:
    """Returns list of technique dicts with keys: id, name, tactics, platforms, description."""
    with open(_path("mitre_techniques.json")) as f:
        return json.load(f)

def load_mitre_full() -> dict:
    """Returns the full raw MITRE ATT&CK bundle (for advanced queries)."""
    with open(_path("mitre_attack.json")) as f:
        return json.load(f)

# ── GitHub Advisories ─────────────────────────────────────────────────────────
def load_github_advisories() -> pd.DataFrame:
    with open(_path("github_advisories_full.json")) as f:
        raw = json.load(f)
    df = pd.DataFrame(raw)
    df["severity"] = df["severity"].fillna("UNKNOWN").str.upper()
    def _eco(row):
        v = row.get("vulnerabilities", [])
        if isinstance(v, list) and v:
            pkg = v[0].get("package", {})
            return pkg.get("ecosystem", "Unknown") if isinstance(pkg, dict) else "Unknown"
        return "Unknown"
    df["ecosystem"] = [_eco(r) for r in raw]
    def _pkg(row):
        v = row.get("vulnerabilities", [])
        if isinstance(v, list) and v:
            pkg = v[0].get("package", {})
            return pkg.get("name", "") if isinstance(pkg, dict) else ""
        return ""
    df["package_name"] = [_pkg(r) for r in raw]
    return df

# ── MSRC ──────────────────────────────────────────────────────────────────────
def load_msrc() -> pd.DataFrame:
    with open(_path("msrc_full.json")) as f:
        raw = json.load(f)
    df = pd.DataFrame(raw)
    return df

# ── HHS Breach ────────────────────────────────────────────────────────────────
def load_hhs() -> pd.DataFrame:
    rows = []
    with open(_path("hhs_breach.csv")) as f:
        for row in csv.DictReader(f):
            rows.append(row)
    df = pd.DataFrame(rows)
    df["Individuals Affected"] = pd.to_numeric(
        df["Individuals Affected"].str.replace(",", ""), errors="coerce"
    )
    df["Breach Submission Date"] = pd.to_datetime(df["Breach Submission Date"], errors="coerce")
    df["year"] = df["Breach Submission Date"].dt.year
    return df

# ── Asset Inventory + Dependency Graph ───────────────────────────────────────
def load_assets() -> pd.DataFrame:
    with open(_path("asset_inventory.json")) as f:
        return pd.DataFrame(json.load(f))

def load_dependency_graph() -> dict:
    with open(_path("dependency_graph.json")) as f:
        return json.load(f)

# ── Convenience: load everything at once ─────────────────────────────────────
def load_all() -> dict:
    """Load all datasets. Returns a dict keyed by name."""
    print("Loading ARIA data sources…")
    data = {
        "nvd":        load_nvd(),
        "epss_full":  load_epss_full(),
        "epss":       load_epss_matched(),
        "kev":        load_kev(),
        "mitre":      load_mitre(),
        "github":     load_github_advisories(),
        "msrc":       load_msrc(),
        "hhs":        load_hhs(),
        "assets":     load_assets(),
        "deps":       load_dependency_graph(),
    }
    print(f"  ✓ NVD        {len(data['nvd']):,} CVEs")
    print(f"  ✓ EPSS       {len(data['epss']):,} matched scores")
    print(f"  ✓ KEV        {len(data['kev']):,} confirmed exploits")
    print(f"  ✓ MITRE      {len(data['mitre']):,} techniques")
    print(f"  ✓ GitHub     {len(data['github']):,} advisories")
    print(f"  ✓ MSRC       {len(data['msrc']):,} Microsoft CVEs")
    print(f"  ✓ HHS        {len(data['hhs']):,} breach records")
    print(f"  ✓ Assets     {len(data['assets']):,} assets")
    print("All sources loaded.\n")
    return data
