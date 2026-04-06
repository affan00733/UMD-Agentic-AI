"""
agent_07_blast.py — Blast Radius Agent
Responsibility: Walk the dependency graph to determine how many downstream
services are affected if a CVE's matched asset is compromised. A vulnerability
in a shared authentication service could expose every service that depends on it.

This is what turns "one server is vulnerable" into "our entire platform is at risk."

Input:  CVE records (from Agent 6) + dependency graph dict
Output: same records + blast_radius (0–1), blast_radius_count, blast_path
"""

from __future__ import annotations
from collections import deque
from typing import Optional

from agents.shared.data_loader import load_assets, load_dependency_graph


def run(cve_records: list[dict]) -> list[dict]:
    """
    For each CVE record with a matched asset, walk the dependency graph
    to compute blast radius.

    Adds:
      - blast_radius         : float 0–1 (normalized by total service count)
      - blast_radius_count   : int (number of downstream services affected)
      - blast_path           : list of service names in the impact chain
      - blast_label          : "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
      - blast_context        : plain-English description for the report
    """
    deps   = load_dependency_graph()
    assets = load_assets()

    # Build forward adjacency: service → [services that depend on it]
    # and reverse adjacency: service → [services it depends on]
    forward, reverse = _build_graph(deps)
    total_services   = len(forward) or 1

    # Normalize asset field names
    name_col = "asset_name" if "asset_name" in assets.columns else "name"
    asset_lookup = {str(a[name_col]).lower(): a for _, a in assets.iterrows()}

    enriched = []

    for rec in cve_records:
        rec = dict(rec)
        asset_name = rec.get("asset_name", "")

        if not asset_name or asset_name == "No direct asset match":
            rec["blast_radius"]       = 0.0
            rec["blast_radius_count"] = 0
            rec["blast_path"]         = []
            rec["blast_label"]        = "NONE"
            rec["blast_context"]      = "No asset matched — blast radius not computable."
            enriched.append(rec)
            continue

        # Find matching service node in graph
        service_node = _find_service_node(asset_name, forward)

        if service_node is None:
            rec["blast_radius"]       = 0.0
            rec["blast_radius_count"] = 0
            rec["blast_path"]         = []
            rec["blast_label"]        = "LOW"
            rec["blast_context"]      = (
                f"Asset '{asset_name}' not found in dependency graph. "
                f"Blast radius assumed minimal."
            )
            enriched.append(rec)
            continue

        # BFS downstream: if this node is compromised, what can an attacker reach?
        downstream = _bfs_downstream(service_node, forward)

        # Also check: what upstream services trust this node (auth/data dependency)?
        upstream_dependents = reverse.get(service_node, set())

        total_blast = len(downstream) + len(upstream_dependents)
        blast_norm  = min(total_blast / total_services, 1.0)

        blast_path = list(downstream)[:10]  # cap at 10 for readability

        rec["blast_radius"]       = round(blast_norm, 3)
        rec["blast_radius_count"] = total_blast
        rec["blast_path"]         = blast_path
        rec["blast_label"]        = _blast_label(blast_norm)
        rec["blast_context"]      = _build_blast_context(
            asset_name, service_node, total_blast,
            blast_path, upstream_dependents,
            rec.get("in_kev", False)
        )
        enriched.append(rec)

    _print_summary(enriched)
    return enriched


def _build_graph(deps: dict) -> tuple[dict, dict]:
    """
    Build forward and reverse adjacency dicts from the dependency graph JSON.

    Expected dep graph format:
      {
        "service_dependencies": [
          {"service": "A", "depends_on": ["B", "C"]},
          ...
        ]
      }
    """
    forward = {}   # service → set of services it depends on
    reverse = {}   # service → set of services that depend on IT

    raw = deps.get("service_dependencies",
          deps.get("dependencies",
          deps.get("services", {})))

    # Support two formats:
    #   dict format: {"svc-a": ["svc-b", "svc-c"], ...}  (our actual data)
    #   list format: [{"service": "svc-a", "depends_on": ["svc-b"]}, ...]
    if isinstance(raw, dict):
        service_deps = [{"service": k, "depends_on": v} for k, v in raw.items()]
    else:
        service_deps = raw if isinstance(raw, list) else []

    for entry in service_deps:
        if isinstance(entry, dict):
            svc      = str(entry.get("service", entry.get("name", ""))).lower()
            dep_list = entry.get("depends_on", entry.get("dependencies", []))
        else:
            continue

        if svc not in forward:
            forward[svc] = set()
        if svc not in reverse:
            reverse[svc] = set()

        for dep in dep_list:
            dep = str(dep).lower()
            forward[svc].add(dep)
            if dep not in forward:
                forward[dep] = set()
            if dep not in reverse:
                reverse[dep] = set()
            reverse[dep].add(svc)   # dep is needed by svc

    return forward, reverse


def _find_service_node(asset_name: str, graph: dict) -> Optional[str]:
    """
    Find the service node in the graph that best matches the asset name.
    Tries exact match, then partial match.
    """
    name_lower = asset_name.lower()

    # Exact match
    if name_lower in graph:
        return name_lower

    # Partial match — asset name contains a graph node or vice versa
    for node in graph:
        if node in name_lower or name_lower in node:
            return node

    # Word-level partial match
    name_words = set(name_lower.split("-"))
    for node in graph:
        node_words = set(node.split("-"))
        if name_words & node_words:
            return node

    return None


def _bfs_downstream(start: str, graph: dict) -> set:
    """
    BFS from start node following forward edges (services that start depends on).
    Returns all reachable nodes (the attack can spread to these via the compromised node).
    """
    visited = set()
    queue   = deque([start])
    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited


def _blast_label(blast_norm: float) -> str:
    if blast_norm >= 0.5:   return "CRITICAL"
    if blast_norm >= 0.25:  return "HIGH"
    if blast_norm >= 0.10:  return "MEDIUM"
    if blast_norm > 0:      return "LOW"
    return "NONE"


def _build_blast_context(
    asset_name:           str,
    service_node:         str,
    total_blast:          int,
    blast_path:           list,
    upstream_dependents:  set,
    in_kev:               bool,
) -> str:
    if total_blast == 0:
        return f"'{asset_name}' has no downstream dependencies — impact is contained."

    path_str = " → ".join(blast_path[:5]) if blast_path else "unknown services"
    upstr    = f" Additionally, {len(upstream_dependents)} service(s) depend on this asset and inherit the risk." if upstream_dependents else ""

    base = (f"If '{asset_name}' is compromised, an attacker can reach "
            f"{total_blast} downstream service(s): {path_str}.{upstr}")

    if in_kev:
        base += " This blast radius is ACTIVE — the CVE is confirmed exploited."
    return base


def _print_summary(records: list[dict]) -> None:
    with_blast = [r for r in records if r["blast_radius"] > 0]
    if not with_blast:
        print(f"[Agent 7] Blast radius: no dependency graph matches found")
        return
    avg_blast = sum(r["blast_radius"] for r in with_blast) / len(with_blast)
    max_r     = max(with_blast, key=lambda r: r["blast_radius"])
    print(f"[Agent 7] Blast radius computed for {len(records)} CVEs:")
    print(f"  CVEs with blast > 0   : {len(with_blast)}")
    print(f"  Avg blast radius      : {avg_blast:.3f}")
    print(f"  Max blast             : {max_r['blast_radius']:.3f} "
          f"({max_r['cve_id']} via '{max_r['asset_name']}')")


if __name__ == "__main__":
    from agents.agent_01_ingest   import run as ingest
    from agents.agent_02_exploit  import run as exploit
    from agents.agent_03_threat   import run as threat
    from agents.agent_04_business import run as business, DEMO_ORG
    from agents.agent_05_assets   import run as assets_agent
    from agents.agent_06_compliance import run as compliance

    cves = ingest()
    cves = exploit(cves)
    cves = threat(cves)
    ctx  = business(DEMO_ORG, "Acme HealthTech")
    cves = assets_agent(cves, ctx)
    cves = compliance(cves, ctx)
    results = run(cves)

    blast = [r for r in results if r["blast_radius"] > 0]
    print(f"\nTop blast radius CVEs ({len(blast)} total):")
    for r in sorted(blast, key=lambda x: -x["blast_radius"])[:5]:
        print(f"  {r['cve_id']}  blast={r['blast_radius']:.3f} ({r['blast_label']})  "
              f"services={r['blast_radius_count']}  via '{r['asset_name']}'")
