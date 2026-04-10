"""
agent_04_business.py — Business Context Agent
Responsibility: Parse a plain-English description of the organization and
extract structured business context: industry, revenue tier, regulated data
types, primary technology stack, and risk tolerance.

LLM USAGE: This agent uses Claude (claude-haiku-3-5) to understand natural
language organization descriptions. Claude is the RIGHT tool here because:
  - Free-text org descriptions use varied phrasing ("we handle patient data"
    vs "we store PHI" vs "we serve hospitals") that regex misses
  - Claude understands business context and can infer compliance obligations
    from implicit cues that keyword matching cannot catch
  - Claude produces structured JSON that maps directly to the BusinessContext schema

FALLBACK: If ANTHROPIC_API_KEY is not set, the agent falls back to keyword-
based pattern matching (same logic as before). The system works either way —
Claude just makes it significantly smarter.

WHY NOT OTHER AGENTS: Agents 1,2,5,6,7,8,9 deal with structured data (JSON,
CSV, graph traversal, math) where LLM adds no value and determinism is required.
"""

from __future__ import annotations
import os, re, json
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class BusinessContext:
    org_name:             str
    industry:             str
    revenue_tier:         str
    employee_count:       Optional[int]
    handles_payments:     bool
    handles_health_data:  bool
    is_technology_company: bool
    handles_eu_data:      bool
    uses_windows:         bool
    uses_cloud:           bool
    uses_open_source:     bool
    primary_stack:        list
    breach_cost_estimate: float
    risk_tolerance:       str
    raw_description:      str
    # Operational constraints (for maintenance window scheduler)
    maintenance_windows:        list  = None   # None → use scheduler defaults
    engineer_hours_per_sprint:  int   = 40     # available engineering hours per 2-week sprint
    patch_budget_per_sprint:    float = 3000.0 # $ budget for patch work per sprint


BREACH_COST_BY_INDUSTRY = {
    "Healthcare":    9_770_000,
    "Finance":       6_080_000,
    "Technology":    4_880_000,
    "Government":    2_590_000,
    "Education":     3_580_000,
    "Retail":        3_480_000,
    "Manufacturing": 4_470_000,
    "Media":         3_580_000,
    "Unknown":       4_880_000,
}

# ── LLM-powered parsing (primary path) ───────────────────────────────────────

_LLM_SYSTEM = """You are a cybersecurity business analyst. Given a plain-English
description of an organization, extract structured business context as JSON.
Return ONLY valid JSON with exactly these keys:
{
  "industry": one of [Healthcare, Finance, Retail, Technology, Government, Education, Manufacturing, Media, Unknown],
  "revenue_tier": one of [startup, smb, enterprise, large_enterprise],
  "employee_count": integer or null,
  "handles_payments": true/false,
  "handles_health_data": true/false,
  "is_technology_company": true/false,
  "handles_eu_data": true/false,
  "uses_windows": true/false,
  "uses_cloud": true/false,
  "uses_open_source": true/false,
  "primary_stack": list of technology names (e.g. ["Python","AWS","PostgreSQL"]),
  "risk_tolerance": one of [low, medium, high]
}

Rules:
- handles_health_data: true if org stores patient records, PHI, EHR, medical data, or serves hospitals/clinics
- handles_payments: true if org processes credit cards, billing, subscriptions, or financial transactions
- is_technology_company: true if org sells software/SaaS/platform or provides tech services
- risk_tolerance: low for Healthcare/Finance/Government; high for startups; medium otherwise
- primary_stack: only include technologies explicitly mentioned or strongly implied"""

_LLM_PROMPT = "Organization description:\n\n{description}\n\nExtract the business context JSON:"


def _parse_with_claude(org_description: str) -> Optional[dict]:
    """Use Claude claude-haiku-3-5 to parse org description. Returns dict or None on failure."""
    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return None
        client  = anthropic.Anthropic(api_key=api_key)
        resp    = client.messages.create(
            model      = "claude-haiku-4-5",
            max_tokens = 512,
            system     = _LLM_SYSTEM,
            messages   = [{"role": "user",
                           "content": _LLM_PROMPT.format(description=org_description)}],
        )
        raw = resp.content[0].text.strip()
        # Strip markdown code fences if present
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        return json.loads(raw)
    except Exception as e:
        print(f"[Agent 4] Claude parsing failed ({e}) — falling back to rule-based")
        return None


# ── Rule-based fallback ───────────────────────────────────────────────────────

INDUSTRY_KEYWORDS = {
    "Healthcare":    ["hospital","clinic","health","medical","patient","ehr","hipaa","pharmacy"],
    "Finance":       ["bank","banking","finance","financial","insurance","investment","trading",
                      "fintech","payment","credit","loan","mortgage"],
    "Retail":        ["retail","ecommerce","e-commerce","store","shop","merchant","checkout"],
    "Technology":    ["software","saas","platform","api","developer","cloud","startup","tech"],
    "Government":    ["government","federal","agency","municipal","public sector","defense"],
    "Education":     ["university","college","school","education","student","campus","academic"],
    "Manufacturing": ["manufactur","factory","factories","industrial","plant","supply chain","logistics","automotive","semiconductor","aerospace","warehouse"],
    "Media":         ["media","publishing","news","broadcast","entertainment","streaming"],
}

TECH_KEYWORDS = {
    "Python": ["python","django","flask","fastapi"],
    "JavaScript": ["javascript","node","nodejs","react","vue","angular","typescript"],
    "Java": ["java","spring","jvm","kotlin"],
    "Go": ["golang"," go "],
    "PHP": ["php","laravel","wordpress"],
    "AWS": ["aws","amazon web services","s3","ec2","lambda"],
    "Azure": ["azure","microsoft cloud"],
    "GCP": ["gcp","google cloud"],
    "PostgreSQL": ["postgres","postgresql"],
    "MySQL": ["mysql"],
    "MongoDB": ["mongodb","mongo"],
    "Docker": ["docker","container"],
    "Kubernetes": ["kubernetes","k8s"],
}


def _parse_rule_based(text: str) -> dict:
    t = text.lower()

    # Industry
    scores = {ind: sum(1 for kw in kws if kw in t)
              for ind, kws in INDUSTRY_KEYWORDS.items()}
    industry = max(scores, key=lambda k: scores[k])
    if scores[industry] == 0:
        industry = "Unknown"

    # Revenue tier
    revenue_tier = "smb"
    if any(kw in t for kw in ["fortune 500","billion","global","multinational","publicly traded"]):
        revenue_tier = "large_enterprise"
    elif any(kw in t for kw in ["million","large company","thousands of employees"]):
        revenue_tier = "enterprise"
    elif any(kw in t for kw in ["startup","start-up","seed","series a","founded","small team"]):
        revenue_tier = "startup"

    # Employee count
    employee_count = None
    m = re.search(r"(\d[\d,]*)\s*(?:full[- ]?time\s+)?employees", t)
    if m:
        employee_count = int(m.group(1).replace(",", ""))

    # Booleans
    handles_payments  = any(kw in t for kw in ["payment","credit card","pci","checkout","billing","transaction"])
    handles_health    = any(kw in t for kw in ["health","patient","medical","hipaa","clinical","ehr","phi","hospital"])
    is_tech           = industry == "Technology" or any(kw in t for kw in ["software","saas","api","platform"])
    handles_eu        = any(kw in t for kw in ["europe","eu ","gdpr","european"])
    uses_windows      = any(kw in t for kw in ["windows","microsoft","active directory","office 365"])
    uses_cloud        = any(kw in t for kw in ["aws","azure","gcp","cloud"])
    uses_oss          = any(kw in t for kw in ["open source","linux","python","node","github"])

    # Stack
    stack = [tech for tech, kws in TECH_KEYWORDS.items() if any(kw in t for kw in kws)]

    # Risk tolerance
    if handles_health or industry in ("Healthcare", "Finance", "Government"):
        risk_tolerance = "low"
    elif any(kw in t for kw in ["startup","move fast","agile"]):
        risk_tolerance = "high"
    else:
        risk_tolerance = "medium"

    return {
        "industry": industry, "revenue_tier": revenue_tier,
        "employee_count": employee_count,
        "handles_payments": handles_payments, "handles_health_data": handles_health,
        "is_technology_company": is_tech, "handles_eu_data": handles_eu,
        "uses_windows": uses_windows, "uses_cloud": uses_cloud,
        "uses_open_source": uses_oss, "primary_stack": stack,
        "risk_tolerance": risk_tolerance,
    }


# ── Main entry point ──────────────────────────────────────────────────────────

def run(org_description: str, org_name: str = "Organization") -> dict:
    """
    Parse org_description and return a BusinessContext dict.
    Uses Claude if ANTHROPIC_API_KEY is set, otherwise rule-based fallback.
    """
    # Try Claude first
    parsed = _parse_with_claude(org_description)
    method = "claude"

    # Fallback to rules
    if parsed is None:
        parsed = _parse_rule_based(org_description)
        method = "rule-based"

    # Merge with defaults and add fields Claude doesn't produce
    industry      = parsed.get("industry", "Unknown")
    breach_cost   = BREACH_COST_BY_INDUSTRY.get(industry, 4_880_000)

    ctx = BusinessContext(
        org_name              = org_name,
        industry              = industry,
        revenue_tier          = parsed.get("revenue_tier", "smb"),
        employee_count        = parsed.get("employee_count"),
        handles_payments      = bool(parsed.get("handles_payments", False)),
        handles_health_data   = bool(parsed.get("handles_health_data", False)),
        is_technology_company = bool(parsed.get("is_technology_company", False)),
        handles_eu_data       = bool(parsed.get("handles_eu_data", False)),
        uses_windows          = bool(parsed.get("uses_windows", False)),
        uses_cloud            = bool(parsed.get("uses_cloud", False)),
        uses_open_source      = bool(parsed.get("uses_open_source", True)),
        primary_stack         = parsed.get("primary_stack", []),
        breach_cost_estimate  = breach_cost,
        risk_tolerance        = parsed.get("risk_tolerance", "medium"),
        raw_description       = org_description,
    )

    _print_summary(ctx, method)
    return asdict(ctx)


def _print_summary(ctx: BusinessContext, method: str) -> None:
    compliance = []
    if ctx.handles_payments:     compliance.append("PCI DSS")
    if ctx.handles_health_data:  compliance.append("HIPAA")
    if ctx.is_technology_company: compliance.append("SOC2")
    if ctx.handles_eu_data:      compliance.append("GDPR")
    print(f"[Agent 4] Business context ({method}) for: {ctx.org_name}")
    print(f"  Industry          : {ctx.industry}")
    print(f"  Revenue tier      : {ctx.revenue_tier}")
    print(f"  Compliance        : {', '.join(compliance) or 'None detected'}")
    print(f"  Primary stack     : {', '.join(ctx.primary_stack[:6]) or 'Unknown'}")
    print(f"  Breach cost est.  : ${ctx.breach_cost_estimate:,.0f}")
    print(f"  Risk tolerance    : {ctx.risk_tolerance}")


DEMO_ORG = """
Acme HealthTech is a mid-size healthcare technology company with 320 employees.
We operate a SaaS platform used by 150 hospitals across the United States.
Our platform stores patient health records (PHI) and integrates with EHR systems.
We process credit card payments for subscription billing.
Our technology stack includes Python (Django), PostgreSQL, AWS (S3, EC2, Lambda),
Docker/Kubernetes, and React on the frontend. We serve enterprise hospital clients
and are SOC2 Type II certified. Our platform must comply with HIPAA regulations.
"""

if __name__ == "__main__":
    ctx = run(DEMO_ORG, org_name="Acme HealthTech")
    print("\nExtracted context:")
    for k, v in ctx.items():
        if k != "raw_description":
            print(f"  {k}: {v}")
