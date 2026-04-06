"""
agent_03_threat.py — Threat Context Agent
Responsibility: Map each CVE's CWE weakness type to MITRE ATT&CK tactics
and techniques. Tells ARIA *what attack phase* a vulnerability enables
and *how many techniques* an attacker has available once they exploit it.

Input:  enriched CVE records from Agent 2
Output: same records + mitre_tactics, mitre_techniques, attack_phase, technique_count
"""

from __future__ import annotations
from collections import defaultdict

from agents.shared.data_loader import load_mitre


# ── CWE → MITRE ATT&CK Tactic mapping ────────────────────────────────────────
# Based on MITRE's official CWE-CAPEC-ATT&CK mapping.
# Each CWE maps to the *primary* tactic it enables.
CWE_TO_TACTIC: dict[str, list[str]] = {
    # Initial Access — entry point vulnerabilities
    "CWE-89":  ["Initial Access", "Execution"],          # SQL Injection
    "CWE-78":  ["Execution", "Initial Access"],          # OS Command Injection
    "CWE-77":  ["Execution"],                            # Command Injection
    "CWE-94":  ["Execution"],                            # Code Injection
    "CWE-434": ["Initial Access"],                       # Unrestricted File Upload
    "CWE-306": ["Initial Access", "Defense Evasion"],    # Missing Authentication
    "CWE-287": ["Initial Access"],                       # Improper Authentication
    "CWE-294": ["Initial Access"],                       # Auth Bypass via Capture-Replay
    "CWE-798": ["Initial Access", "Credential Access"],  # Hard-coded Credentials

    # Privilege Escalation
    "CWE-269": ["Privilege Escalation"],                 # Improper Privilege Management
    "CWE-732": ["Privilege Escalation"],                 # Incorrect Permission Assignment
    "CWE-276": ["Privilege Escalation"],                 # Incorrect Default Permissions

    # Credential Access
    "CWE-256": ["Credential Access"],                    # Plaintext Password Storage
    "CWE-522": ["Credential Access"],                    # Insufficiently Protected Credentials
    "CWE-916": ["Credential Access"],                    # Weak Password Hash

    # Defense Evasion / Persistence
    "CWE-502": ["Execution", "Persistence"],             # Deserialization
    "CWE-918": ["Defense Evasion", "Collection"],        # SSRF
    "CWE-601": ["Defense Evasion", "Initial Access"],    # Open Redirect
    "CWE-352": ["Initial Access", "Execution"],          # CSRF

    # Collection / Exfiltration
    "CWE-22":  ["Collection", "Exfiltration"],           # Path Traversal
    "CWE-23":  ["Collection", "Exfiltration"],           # Relative Path Traversal
    "CWE-200": ["Collection"],                           # Info Exposure
    "CWE-538": ["Collection"],                           # File/Path Info Exposure
    "CWE-359": ["Collection"],                           # Privacy Violation

    # Impact / Availability
    "CWE-400": ["Impact"],                               # Uncontrolled Resource Consumption
    "CWE-770": ["Impact"],                               # Resource Allocation Without Limits
    "CWE-674": ["Impact"],                               # Uncontrolled Recursion
    "CWE-772": ["Impact"],                               # Missing Resource Release

    # Memory Corruption / Execution (very high severity)
    "CWE-119": ["Execution", "Privilege Escalation"],    # Buffer Overflow (generic)
    "CWE-120": ["Execution", "Privilege Escalation"],    # Buffer Copy (classic overflow)
    "CWE-125": ["Collection", "Privilege Escalation"],   # Out-of-bounds Read
    "CWE-787": ["Execution", "Privilege Escalation"],    # Out-of-bounds Write
    "CWE-416": ["Execution", "Privilege Escalation"],    # Use-After-Free
    "CWE-476": ["Impact"],                               # NULL Pointer Dereference
    "CWE-824": ["Execution"],                            # Uninitialized Pointer
    "CWE-823": ["Execution", "Privilege Escalation"],    # Use of Out-of-Range Pointer
    "CWE-415": ["Execution"],                            # Double Free

    # Web / XSS
    "CWE-79":  ["Collection", "Defense Evasion"],        # XSS
    "CWE-80":  ["Collection"],                           # Stored XSS (Basic)

    # Authorization
    "CWE-862": ["Privilege Escalation", "Collection"],   # Missing Authorization
    "CWE-863": ["Privilege Escalation"],                 # Incorrect Authorization
    "CWE-639": ["Collection"],                           # IDOR (Insecure Direct Object Ref)
    "CWE-284": ["Privilege Escalation"],                 # Improper Access Control

    # Cryptography
    "CWE-327": ["Defense Evasion"],                      # Broken/Risky Crypto
    "CWE-326": ["Defense Evasion"],                      # Inadequate Encryption Strength
    "CWE-295": ["Defense Evasion", "Initial Access"],    # Improper Cert Validation

    # XXE / SSRF / Injection (misc)
    "CWE-611": ["Collection", "Exfiltration"],           # XXE
    "CWE-91":  ["Execution", "Collection"],              # XML Injection
    "CWE-90":  ["Initial Access"],                       # LDAP Injection
}

# Priority tactic for sorting (lower = higher priority for remediation)
TACTIC_PRIORITY = {
    "Initial Access":       1,
    "Execution":            2,
    "Privilege Escalation": 3,
    "Credential Access":    4,
    "Lateral Movement":     5,
    "Collection":           6,
    "Exfiltration":         7,
    "Impact":               8,
    "Persistence":          9,
    "Defense Evasion":      10,
}


def run(cve_records: list[dict]) -> list[dict]:
    """
    Enrich each CVE record with:
      - mitre_tactics      : list of ATT&CK tactic names
      - mitre_techniques   : list of {id, name, tactic} dicts
      - primary_tactic     : the highest-priority tactic for this CVE
      - attack_phase       : human-readable label ("Entry Point", "Execution", etc.)
      - technique_count    : how many MITRE techniques are available to exploit this
      - threat_context     : plain-English sentence for the report

    Returns the same list with MITRE fields added.
    """
    techniques = load_mitre()

    # Build tactic → technique list index
    tactic_to_techniques: dict[str, list[dict]] = defaultdict(list)
    for t in techniques:
        for tac in t.get("tactics", []):
            tactic_to_techniques[tac].append({
                "id":     t.get("id", ""),
                "name":   t.get("name", ""),
                "tactic": tac,
            })

    enriched = []
    unmatched_cwes = set()

    for rec in cve_records:
        rec = dict(rec)
        cwe = rec.get("cwe", "UNKNOWN")

        tactics   = CWE_TO_TACTIC.get(cwe, [])
        if not tactics:
            unmatched_cwes.add(cwe)
            tactics = ["Unknown"]

        # Collect techniques for all mapped tactics
        matched_techniques = []
        for tac in tactics:
            matched_techniques.extend(tactic_to_techniques.get(tac, [])[:5])  # top 5 per tactic

        # Primary tactic = highest priority one
        primary = min(tactics, key=lambda t: TACTIC_PRIORITY.get(t, 99))

        rec["mitre_tactics"]    = tactics
        rec["mitre_techniques"] = matched_techniques
        rec["primary_tactic"]   = primary
        rec["attack_phase"]     = _attack_phase_label(primary)
        rec["technique_count"]  = len(tactic_to_techniques.get(primary, []))
        rec["threat_context"]   = _build_threat_context(
            rec["cve_id"], cwe, primary, rec["technique_count"],
            rec.get("in_kev", False), rec.get("ransomware", False)
        )
        enriched.append(rec)

    if unmatched_cwes:
        print(f"[Agent 3] {len(unmatched_cwes)} CWE(s) not in mapping "
              f"(labelled 'Unknown'): {', '.join(sorted(unmatched_cwes)[:8])}")

    # Tactic distribution summary
    tactic_counts = defaultdict(int)
    for r in enriched:
        tactic_counts[r["primary_tactic"]] += 1
    top_tactics = sorted(tactic_counts.items(), key=lambda x: -x[1])[:5]

    print(f"[Agent 3] MITRE ATT&CK context mapped for {len(enriched)} CVEs")
    print(f"  Top attack phases: " +
          ", ".join(f"{t} ({c})" for t, c in top_tactics))
    return enriched


def _attack_phase_label(tactic: str) -> str:
    labels = {
        "Initial Access":       "Entry Point (attacker gets in)",
        "Execution":            "Code Execution (attacker runs commands)",
        "Privilege Escalation": "Privilege Escalation (attacker gains admin)",
        "Credential Access":    "Credential Theft (attacker steals passwords)",
        "Lateral Movement":     "Lateral Movement (attacker spreads through network)",
        "Collection":           "Data Collection (attacker gathers sensitive data)",
        "Exfiltration":         "Data Theft (attacker steals data out)",
        "Impact":               "Availability Impact (denial of service / disruption)",
        "Persistence":          "Persistence (attacker maintains long-term access)",
        "Defense Evasion":      "Evasion (attacker hides their activity)",
        "Unknown":              "Attack Phase Unknown",
    }
    return labels.get(tactic, tactic)


def _build_threat_context(
    cve_id: str,
    cwe: str,
    primary_tactic: str,
    technique_count: int,
    in_kev: bool,
    ransomware: bool,
) -> str:
    phase = _attack_phase_label(primary_tactic)
    base  = (f"{cve_id} ({cwe}) enables {phase}. "
             f"An attacker has {technique_count} known techniques available "
             f"at this attack phase.")
    if ransomware:
        base += " This vulnerability is used as a ransomware entry point."
    elif in_kev:
        base += " Actively exploited in the wild (CISA KEV confirmed)."
    return base


if __name__ == "__main__":
    from agents.agent_01_ingest import run as ingest
    from agents.agent_02_exploit import run as exploit
    cves    = ingest()
    cves    = exploit(cves)
    results = run(cves)
    print(f"\nTop 5 with MITRE context:")
    for r in results[:5]:
        print(f"  {r['cve_id']}  Tactic={r['primary_tactic']}  "
              f"Phase='{r['attack_phase']}'  Techniques={r['technique_count']}")
