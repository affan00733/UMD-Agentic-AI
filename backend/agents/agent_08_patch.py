"""
agent_08_patch.py — Patch Feasibility Agent
Responsibility: For each CVE, determine whether a patch exists and flag any
potential conflicts. Uses GitHub Security Advisories (open-source packages)
and Microsoft MSRC (Windows/Office/Azure).

ARIA hard gate: if patch_available=False, output is "Monitor" not "Patch now."
Pre-patch conflict detection: if upgrading a package would break a dependency,
the report flags it BEFORE the team installs anything.

Input:  CVE records (from Agent 7)
Output: same records + patch_available, patch_version, patch_source, patch_conflict
"""

from __future__ import annotations
from typing import Optional

from agents.shared.data_loader import load_github_advisories, load_msrc
from agents.agent_01_ingest import extract_vendor_from_cpe


# Vendors covered by MSRC
MSRC_VENDORS = {
    "microsoft", "windows", "azure", "office", "exchange",
    "sharepoint", ".net", "visual studio", "iis", "edge",
    "sql server", "teams", "outlook"
}


def run(cve_records: list[dict]) -> list[dict]:
    """
    Enrich each CVE record with:
      - patch_available    : True / False / None (unknown)
      - patch_version      : str (e.g. "4.18.3") or ""
      - patch_source       : "GitHub" / "MSRC" / "Vendor Advisory" / "Unknown"
      - patch_url          : advisory URL if available
      - patch_conflict     : bool — upgrading might break a dependency
      - patch_conflict_note: plain-English explanation of conflict if any
      - patch_action       : "PATCH NOW" / "MONITOR" / "WORKAROUND" / "UNKNOWN"
      - patch_context      : plain-English sentence for the report
    """
    github_df = load_github_advisories()
    msrc_df   = load_msrc()

    # Build CVE-ID → advisory lookup for GitHub
    gh_lookup: dict[str, list[dict]] = {}
    for _, row in github_df.iterrows():
        cid = row.get("cve_id", "")
        if cid and isinstance(cid, str) and cid.startswith("CVE-"):
            gh_lookup.setdefault(cid, []).append(row.to_dict())

    # Build CVE-ID → MSRC row lookup
    msrc_lookup: dict[str, dict] = {}
    if "cve_id" in msrc_df.columns:
        for _, row in msrc_df.iterrows():
            cid = row.get("cve_id", "")
            if cid:
                msrc_lookup[cid] = row.to_dict()

    enriched = []
    stats = {"patched": 0, "no_patch": 0, "unknown": 0, "conflict": 0}

    for rec in cve_records:
        rec    = dict(rec)
        cve_id = rec["cve_id"]

        patch_available   = None
        patch_version     = ""
        patch_source      = "Unknown"
        patch_url         = ""
        patch_conflict    = False
        conflict_note     = ""

        # ── Check GitHub Advisories ───────────────────────────────────────────
        if cve_id in gh_lookup:
            gh_rows = gh_lookup[cve_id]
            patch_available = True
            patch_source    = "GitHub"
            # Extract patched version from first advisory
            for gh_row in gh_rows:
                vulns = gh_row.get("vulnerabilities", [])
                if isinstance(vulns, list):
                    for v in vulns:
                        if isinstance(v, dict):
                            patched = v.get("patched_versions", "")
                            if patched and patched not in ("*", ""):
                                patch_version = str(patched)
                                break
                url = gh_row.get("html_url", gh_row.get("url", ""))
                if url:
                    patch_url = url
                break   # first advisory is sufficient

            # Conflict detection: if patch_version is a major version bump
            patch_conflict, conflict_note = _detect_conflict(
                rec, patch_version, gh_rows
            )
            if patch_conflict:
                stats["conflict"] += 1

        # ── Check MSRC ────────────────────────────────────────────────────────
        elif _is_msrc_vendor(rec):
            if cve_id in msrc_lookup:
                msrc_row = msrc_lookup[cve_id]
                has_patch = msrc_row.get("has_patch", False)
                patch_available = bool(has_patch)
                patch_source    = "MSRC"
                patch_url       = msrc_row.get("url", msrc_row.get("advisory_url", ""))
            else:
                # MSRC vendor but not in our dataset — check by severity signal
                patch_source = "MSRC"
                # Microsoft typically patches on Patch Tuesday; assume available for older CVEs
                year = rec.get("year")
                patch_available = True if (year and year < 2025) else None

        # ── Fallback: infer from age ──────────────────────────────────────────
        else:
            year = rec.get("year")
            if year and year <= 2023:
                patch_available = True    # high likelihood for older CVEs
                patch_source    = "Vendor Advisory (inferred)"
            else:
                patch_available = None    # too new to infer

        # ── Determine recommended action ──────────────────────────────────────
        action = _patch_action(patch_available, patch_conflict, rec)

        rec["patch_available"]    = patch_available
        rec["patch_version"]      = patch_version
        rec["patch_source"]       = patch_source
        rec["patch_url"]          = patch_url
        rec["patch_conflict"]     = patch_conflict
        rec["patch_conflict_note"]= conflict_note
        rec["patch_action"]       = action
        rec["patch_context"]      = _build_patch_context(
            cve_id, patch_available, patch_version, patch_source,
            patch_conflict, conflict_note, action
        )

        if patch_available is True:   stats["patched"] += 1
        elif patch_available is False: stats["no_patch"] += 1
        else:                          stats["unknown"] += 1

        enriched.append(rec)

    _print_summary(enriched, stats)
    return enriched


def _is_msrc_vendor(rec: dict) -> bool:
    """Return True if this CVE is likely covered by MSRC."""
    desc = rec.get("description", "").lower()
    if any(v in desc for v in MSRC_VENDORS):
        return True
    for cpe in rec.get("affected", []):
        vendor = extract_vendor_from_cpe(cpe).lower()
        if vendor == "microsoft":
            return True
    return False


def _detect_conflict(
    rec:           dict,
    patch_version: str,
    gh_rows:       list[dict],
) -> tuple[bool, str]:
    """
    Simple conflict detection: flag if the patch requires a major version change
    (e.g. 2.x → 3.x) which often breaks API compatibility.
    """
    if not patch_version:
        return False, ""

    # Check for major version change indicator
    vuln_range = ""
    for gh_row in gh_rows:
        vulns = gh_row.get("vulnerabilities", [])
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    vuln_range = v.get("vulnerable_version_range", "")
                    break

    if not vuln_range or not patch_version:
        return False, ""

    # If patch_version starts with a different major number than vuln range → conflict risk
    try:
        patch_major = int(patch_version.lstrip(">=^~").split(".")[0])
        # Extract major from vulnerable range (e.g. "< 3.0.0" → 3)
        import re
        range_nums = re.findall(r"\d+", vuln_range)
        if range_nums:
            range_major = int(range_nums[0])
            if patch_major > range_major:
                return True, (
                    f"Patch requires upgrading to v{patch_version} (major version change). "
                    f"This may break API compatibility with services that depend on "
                    f"the current version. Test in staging before deploying."
                )
    except (ValueError, IndexError):
        pass

    return False, ""


def _patch_action(
    patch_available: Optional[bool],
    patch_conflict:  bool,
    rec:             dict,
) -> str:
    # KEV/Ransomware always gets an emergency action regardless of patch status.
    # These are confirmed active exploits — the security team must act NOW even if
    # the patch status is unknown; they escalate to the vendor directly.
    if rec.get("in_kev"):
        if patch_available is True and not patch_conflict:
            return "PATCH NOW — EMERGENCY"
        return "PATCH NOW — EMERGENCY (patch not yet confirmed; apply mitigations + contact vendor)"
    if rec.get("ransomware"):
        if patch_available is True and not patch_conflict:
            return "PATCH NOW — EMERGENCY"
        return "PATCH NOW — EMERGENCY (ransomware-linked; apply mitigations immediately)"

    if patch_available is False:
        return "MONITOR"
    if patch_available is True and not patch_conflict:
        if rec.get("exploit_priority") in ("CRITICAL", "HIGH"):
            return "PATCH NOW"
        return "PATCH — SCHEDULED"
    if patch_available is True and patch_conflict:
        return "PATCH WITH CAUTION — Test in staging first"
    return "UNKNOWN — Check vendor advisory"


def _build_patch_context(
    cve_id:          str,
    patch_available: Optional[bool],
    patch_version:   str,
    patch_source:    str,
    patch_conflict:  bool,
    conflict_note:   str,
    action:          str,
) -> str:
    if patch_available is True:
        ver_str = f" (version: {patch_version})" if patch_version else ""
        conflict_str = f" ⚠ CONFLICT: {conflict_note}" if patch_conflict else ""
        return f"Patch available via {patch_source}{ver_str}. Action: {action}.{conflict_str}"
    elif patch_available is False:
        return f"No patch available yet. Action: MONITOR for vendor update from {patch_source}."
    return f"Patch status unknown. Check {patch_source} or vendor advisory directly."


def _print_summary(records: list[dict], stats: dict) -> None:
    print(f"[Agent 8] Patch feasibility for {len(records)} CVEs:")
    print(f"  Patch available    : {stats['patched']}")
    print(f"  No patch yet       : {stats['no_patch']}")
    print(f"  Unknown            : {stats['unknown']}")
    print(f"  Conflict flagged   : {stats['conflict']}")


if __name__ == "__main__":
    from agents.agent_01_ingest   import run as ingest
    from agents.agent_02_exploit  import run as exploit
    from agents.agent_03_threat   import run as threat
    from agents.agent_04_business import run as business, DEMO_ORG
    from agents.agent_05_assets   import run as assets_agent
    from agents.agent_06_compliance import run as compliance
    from agents.agent_07_blast    import run as blast

    cves = ingest()
    cves = exploit(cves)
    cves = threat(cves)
    ctx  = business(DEMO_ORG, "Acme HealthTech")
    cves = assets_agent(cves, ctx)
    cves = compliance(cves, ctx)
    cves = blast(cves)
    results = run(cves)

    print(f"\nSample patch status:")
    for r in results[:5]:
        print(f"  {r['cve_id']}  patch={r['patch_available']}  "
              f"src={r['patch_source']}  action={r['patch_action']}")
