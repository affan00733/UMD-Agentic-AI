"""
agent_07_blast.py — Blast Radius Agent
Responsibility: For each CVE with a matched asset, compute how many systems
in the environment would be impacted if this vulnerability were exploited.

THREE-LAYER blast radius computation (each is a fallback for the previous):

  Layer 1 — Dependency Graph BFS
    Walk the service dependency graph to find downstream services that would
    cascade-fail if the matched asset is compromised. Best for infrastructure
    CVEs affecting API gateways, auth services, and shared databases.

  Layer 2 — Software-Spread Count (NEW — fixes the zero-blast flaw)
    When the matched asset is not in the dependency graph, count every other
    asset in the inventory that runs the same vulnerable software packages.
    This is the correct model for library CVEs (log4j, openssl, nginx) which
    hit every machine running them simultaneously — not just graph neighbors.

  Layer 3 — CWE + Criticality Heuristic (final fallback)
    When neither graph nor software spread produces a count, use the CVE's
    weakness category and asset criticality to estimate minimum blast radius.
    High-criticality internet-facing assets always have some downstream risk.

The final blast_radius is MAX(Layer1, Layer2, Layer3) — we take the highest
credible estimate and record which method produced it (blast_method field).

WHY THIS MATTERS FOR SCORING:
  The ARIA scoring formula includes (1 + blast_radius) as a multiplier.
  A false zero blast radius suppresses CVE scores on assets that are not in
  the dependency graph — most assets. This fix ensures every matched CVE
  receives a blast radius that reflects real environmental risk, not just
  graph coverage.
"""

from __future__ import annotations
from collections import deque
from typing import Optional

from agents.shared.data_loader import load_assets, load_dependency_graph
from agents.agent_01_ingest import extract_vendor_from_cpe, extract_product_from_cpe


# ── CWE → minimum blast radius heuristic (Layer 3) ────────────────────────────
# Based on attack category: lateral-movement bugs get higher base blast.
CWE_BASE_BLAST: dict[str, float] = {
    # Remote code execution — full lateral movement potential
    "CWE-78":  0.35,   # OS Command Injection
    "CWE-77":  0.35,   # Command Injection
    "CWE-94":  0.35,   # Code Injection
    "CWE-787": 0.30,   # Out-of-bounds Write (RCE)
    "CWE-416": 0.25,   # Use-After-Free (RCE)
    "CWE-119": 0.25,   # Buffer Overflow
    "CWE-502": 0.30,   # Deserialization (RCE)
    # Auth bypass — attacker pivots everywhere
    "CWE-287": 0.40,   # Improper Authentication
    "CWE-306": 0.35,   # Missing Authentication
    "CWE-798": 0.35,   # Hard-coded Credentials
    # SQL/data injection — hits every DB consumer
    "CWE-89":  0.25,   # SQL Injection
    "CWE-611": 0.20,   # XXE
    "CWE-918": 0.20,   # SSRF (pivots to internal services)
    # Privilege escalation — local but affects host
    "CWE-269": 0.15,   # Improper Privilege Management
    "CWE-732": 0.15,   # Incorrect Permission Assignment
    # Info disclosure — data exposure, limited lateral spread
    "CWE-200": 0.10,
    "CWE-22":  0.10,
    "CWE-79":  0.05,   # XSS — client-side only
}

CRITICALITY_MULTIPLIER = {"critical": 1.5, "high": 1.2, "medium": 1.0, "low": 0.7}
INTERNET_FACING_BOOST  = 1.3   # internet-facing assets have wider blast reach


def run(cve_records: list[dict]) -> list[dict]:
    """
    Enrich each CVE record with blast radius using three-layer fallback.

    Adds:
      - blast_radius         : float 0–1 (normalized)
      - blast_radius_count   : int (number of systems at risk)
      - blast_path           : list of affected service/asset names
      - blast_label          : "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "NONE"
      - blast_method         : which layer computed the result
      - blast_context        : plain-English description for the report
    """
    deps   = load_dependency_graph()
    assets = load_assets()

    # Build graph from dependency data
    forward, reverse = _build_graph(deps)
    total_services   = max(len(forward), 1)

    # Build asset lookup: name → asset dict
    name_col     = "asset_name" if "asset_name" in assets.columns else "name"
    asset_lookup = {str(row[name_col]).lower(): row.to_dict()
                    for _, row in assets.iterrows()}
    total_assets = len(assets)

    enriched = []
    method_counts = {"graph": 0, "software_spread": 0, "heuristic": 0, "none": 0}

    for rec in cve_records:
        rec = dict(rec)
        asset_name = rec.get("asset_name", "")

        if not asset_name or asset_name == "No direct asset match":
            rec["blast_radius"]       = 0.0
            rec["blast_radius_count"] = 0
            rec["blast_path"]         = []
            rec["blast_label"]        = "NONE"
            rec["blast_method"]       = "none"
            rec["blast_context"]      = "No asset matched — blast radius not computable."
            method_counts["none"] += 1
            enriched.append(rec)
            continue

        matched_asset = asset_lookup.get(asset_name.lower(), {})

        # ── Layer 1: Dependency graph BFS ─────────────────────────────────────
        graph_count, graph_path, graph_radius = _graph_blast(
            asset_name, forward, reverse, total_services
        )

        # ── Layer 2: Software-spread count ────────────────────────────────────
        spread_count, spread_path, spread_radius = _software_spread_blast(
            rec, assets, matched_asset, asset_name, total_assets
        )

        # ── Layer 3: CWE + criticality heuristic ──────────────────────────────
        heuristic_radius = _heuristic_blast(rec, matched_asset)

        # ── Pick the best (highest credible) estimate ──────────────────────────
        candidates = [
            (graph_radius,     "graph",           graph_count,  graph_path),
            (spread_radius,    "software_spread", spread_count, spread_path),
            (heuristic_radius, "heuristic",       0,            []),
        ]
        best_radius, best_method, best_count, best_path = max(
            candidates, key=lambda x: x[0]
        )

        method_counts[best_method] = method_counts.get(best_method, 0) + 1

        # If spread or heuristic won, count = assets-at-risk for those
        if best_method == "heuristic" and best_count == 0:
            # Convert fractional radius to approximate count for display
            best_count = max(1, round(best_radius * total_assets))
            best_path  = ["(estimated from CWE + asset criticality)"]

        rec["blast_radius"]       = round(best_radius, 3)
        rec["blast_radius_count"] = best_count
        rec["blast_path"]         = best_path[:10]
        rec["blast_label"]        = _blast_label(best_radius)
        rec["blast_method"]       = best_method
        rec["blast_context"]      = _build_blast_context(
            asset_name, best_count, best_path, best_method,
            rec.get("in_kev", False), rec.get("ransomware", False)
        )
        enriched.append(rec)

    _print_summary(enriched, method_counts)
    return enriched


# ── Layer 1: Dependency graph BFS ─────────────────────────────────────────────

def _graph_blast(
    asset_name: str,
    forward:    dict,
    reverse:    dict,
    total:      int,
) -> tuple[int, list, float]:
    """BFS from matched asset in the dependency graph. Returns (count, path, radius)."""
    service_node = _find_service_node(asset_name, forward)
    if service_node is None:
        return 0, [], 0.0

    downstream          = _bfs_downstream(service_node, forward)
    upstream_dependents = reverse.get(service_node, set())
    total_blast         = len(downstream) + len(upstream_dependents)
    blast_path          = list(downstream)[:10]
    radius              = round(min(total_blast / total, 1.0), 3)
    return total_blast, blast_path, radius


def _build_graph(deps: dict) -> tuple[dict, dict]:
    forward = {}
    reverse = {}

    raw = deps.get("service_dependencies",
          deps.get("dependencies",
          deps.get("services", {})))

    if isinstance(raw, dict):
        service_deps = [{"service": k, "depends_on": v} for k, v in raw.items()]
    else:
        service_deps = raw if isinstance(raw, list) else []

    for entry in service_deps:
        if not isinstance(entry, dict):
            continue
        svc      = str(entry.get("service", entry.get("name", ""))).lower()
        dep_list = entry.get("depends_on", entry.get("dependencies", []))

        forward.setdefault(svc, set())
        reverse.setdefault(svc, set())

        for dep in dep_list:
            dep = str(dep).lower()
            forward[svc].add(dep)
            forward.setdefault(dep, set())
            reverse.setdefault(dep, set())
            reverse[dep].add(svc)

    return forward, reverse


def _find_service_node(asset_name: str, graph: dict) -> Optional[str]:
    name_lower = asset_name.lower()

    if name_lower in graph:
        return name_lower

    for node in graph:
        if node in name_lower or name_lower in node:
            return node

    name_words = set(name_lower.replace("-", " ").replace("_", " ").split())
    for node in graph:
        node_words = set(node.replace("-", " ").replace("_", " ").split())
        if name_words & node_words:
            return node

    return None


def _bfs_downstream(start: str, graph: dict) -> set:
    visited = set()
    queue   = deque([start])
    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited


# ── Layer 2: Software-spread blast radius ─────────────────────────────────────

def _software_spread_blast(
    rec:           dict,
    assets_df,
    matched_asset: dict,
    matched_name:  str,
    total_assets:  int,
) -> tuple[int, list, float]:
    """
    Count every other asset in the inventory that runs the same vulnerable
    software as the matched asset, or software named in the CVE.

    This correctly models library/framework CVEs (log4j, openssl, nginx, etc.)
    which affect every machine running them — not just service graph neighbors.
    """
    # Collect identifiers of the vulnerable software from the CVE
    cve_vendors  = set()
    cve_products = set()
    for cpe in rec.get("affected", []):
        v = extract_vendor_from_cpe(cpe).lower()
        p = extract_product_from_cpe(cpe).lower().replace("_", " ")
        if v: cve_vendors.add(v)
        if p: cve_products.add(p)

    description = rec.get("description", "").lower()

    # Get the matched asset's software stack as reference
    matched_stack = _get_stack(matched_asset)
    matched_pkgs  = {s.split("/")[0].split("-")[0] for s in matched_stack if len(s) >= 3}

    at_risk = []
    name_col = "asset_name" if "asset_name" in assets_df.columns else "name"

    for _, row in assets_df.iterrows():
        a = row.to_dict()
        aname = str(a.get(name_col, a.get("asset_name", ""))).lower()
        if aname == matched_name.lower():
            continue  # skip the already-matched asset

        stack      = _get_stack(a)
        stack_pkgs = {s.split("/")[0].split("-")[0] for s in stack if len(s) >= 3}

        hit = False

        # Check 1: CVE vendor name appears in this asset's stack
        for vendor in cve_vendors:
            from agents.agent_05_assets import VENDOR_TO_STACK_KEYWORDS
            kws = VENDOR_TO_STACK_KEYWORDS.get(vendor, [vendor])
            if any(kw in s for kw in kws for s in stack):
                hit = True
                break

        # Check 2: CVE product name appears in this asset's stack
        if not hit:
            for prod in cve_products:
                if prod and len(prod) >= 3 and any(prod in s for s in stack):
                    hit = True
                    break

        # Check 3: Specific package named in CVE description appears in stack
        if not hit:
            for pkg in stack_pkgs:
                if len(pkg) >= 4 and pkg in description:
                    hit = True
                    break

        # Check 4: This asset shares ≥2 software packages with the matched asset
        # (same tech stack = same library exposure)
        if not hit:
            shared = matched_pkgs & stack_pkgs
            if len(shared) >= 2:
                hit = True

        if hit:
            crit_label = str(a.get("criticality", "low")).lower()
            at_risk.append(a.get(name_col, a.get("asset_name", str(aname))))

    count  = len(at_risk)
    radius = round(min(count / max(total_assets, 1), 1.0), 3)
    return count, at_risk[:10], radius


def _get_stack(asset: dict) -> list[str]:
    stack = asset.get("software_installed", asset.get("software_stack", []))
    if not isinstance(stack, list):
        stack = [str(stack)]
    return [s.lower() for s in stack]


# ── Layer 3: CWE + criticality heuristic ──────────────────────────────────────

def _heuristic_blast(rec: dict, matched_asset: dict) -> float:
    """
    When neither graph nor software spread can produce a count,
    use the CVE's weakness type and asset properties to estimate
    a minimum blast radius. Always returns > 0 for matched, critical CVEs.
    """
    cwe         = rec.get("cwe", "UNKNOWN")
    criticality = str(matched_asset.get("criticality", "medium")).lower()
    internet    = bool(matched_asset.get("internet_facing", False))
    in_kev      = bool(rec.get("in_kev", False))
    ransomware  = bool(rec.get("ransomware", False))

    base = CWE_BASE_BLAST.get(cwe, 0.05)   # 0.05 minimum for any known CWE

    crit_mult  = CRITICALITY_MULTIPLIER.get(criticality, 1.0)
    inet_mult  = INTERNET_FACING_BOOST if internet else 1.0
    kev_boost  = 1.5 if in_kev else 1.0
    rw_boost   = 1.3 if ransomware else 1.0

    result = base * crit_mult * inet_mult * kev_boost * rw_boost
    return round(min(result, 0.85), 3)    # cap at 0.85 — heuristic never claims full blast


# ── Labels and context ─────────────────────────────────────────────────────────

def _blast_label(blast_norm: float) -> str:
    if blast_norm >= 0.50:  return "CRITICAL"
    if blast_norm >= 0.25:  return "HIGH"
    if blast_norm >= 0.10:  return "MEDIUM"
    if blast_norm > 0.0:    return "LOW"
    return "NONE"


def _build_blast_context(
    asset_name: str,
    count:      int,
    path:       list,
    method:     str,
    in_kev:     bool,
    ransomware: bool,
) -> str:
    method_labels = {
        "graph":           "dependency graph traversal",
        "software_spread": "software-spread analysis (shared packages)",
        "heuristic":       "CWE + asset criticality estimation",
        "none":            "no analysis possible",
    }
    method_str = method_labels.get(method, method)

    if count == 0:
        return f"'{asset_name}' has no detectable downstream impact."

    path_str = ", ".join(str(p) for p in path[:5]) if path else "other systems"
    if path and path[0].startswith("("):
        path_str = ""   # don't print the heuristic annotation

    base = (f"If '{asset_name}' is compromised, {count} additional "
            f"system(s) are at risk [{method_str}]"
            + (f": {path_str}" if path_str else "") + ".")

    if ransomware:
        base += " Ransomware groups actively use this attack vector — lateral spread is likely."
    elif in_kev:
        base += " This blast radius is ACTIVE — the CVE is confirmed exploited in the wild."

    return base


def _print_summary(records: list[dict], method_counts: dict) -> None:
    with_blast = [r for r in records if r["blast_radius"] > 0]
    total      = len(records)
    print(f"[Agent 7] Blast radius computed for {total} CVEs:")
    print(f"  With blast > 0        : {len(with_blast)} / {total}")
    if with_blast:
        avg = sum(r["blast_radius"] for r in with_blast) / len(with_blast)
        top = max(with_blast, key=lambda r: r["blast_radius"])
        print(f"  Avg blast radius      : {avg:.3f}")
        print(f"  Max blast             : {top['blast_radius']:.3f} "
              f"({top['cve_id']} via '{top['asset_name']}')")
    print(f"  Method breakdown      : "
          f"Graph={method_counts.get('graph',0)}  "
          f"Software-spread={method_counts.get('software_spread',0)}  "
          f"Heuristic={method_counts.get('heuristic',0)}  "
          f"None={method_counts.get('none',0)}")


if __name__ == "__main__":
    from agents.agent_01_ingest    import run as ingest
    from agents.agent_02_exploit   import run as exploit
    from agents.agent_03_threat    import run as threat
    from agents.agent_04_business  import run as business, DEMO_ORG
    from agents.agent_05_assets    import run as assets_agent
    from agents.agent_06_compliance import run as compliance

    cves = ingest()
    cves = exploit(cves)
    cves = threat(cves)
    ctx  = business(DEMO_ORG, "Acme HealthTech")
    cves = assets_agent(cves, ctx)
    cves = compliance(cves, ctx)
    results = run(cves)

    blast = [r for r in results if r["blast_radius"] > 0]
    print(f"\nTop 10 blast radius CVEs ({len(blast)} with blast > 0):")
    for r in sorted(blast, key=lambda x: -x["blast_radius"])[:10]:
        print(f"  {r['cve_id']}  blast={r['blast_radius']:.3f} "
              f"({r['blast_label']})  count={r['blast_radius_count']}  "
              f"method={r['blast_method']}  asset='{r['asset_name']}'")
