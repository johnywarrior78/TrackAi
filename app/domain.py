import re
from dataclasses import dataclass, field
from typing import Any
import yaml

CVE = re.compile(r"CVE-\d{4}-\d{4,19}", re.I)
GHSA = re.compile(
    r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}",
    re.I,
)
CATEGORIES = {"autonomous", "human_assisted", "credited_only", "unverified", "unknown"}
ORGANIZATIONS = {
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "big sleep": "Google DeepMind",
    "deepmind": "Google DeepMind",
    "mdash": "Microsoft",
    "depthfirst": "DepthFirst AI",
}


def identifier(value):
    value = value.strip()
    if CVE.fullmatch(value):
        return value.upper(), "CVE"
    if GHSA.fullmatch(value):
        return "GHSA-" + value[5:].lower(), "GHSA"
    raise ValueError(f"Invalid public identifier: {value[:100]}")


@dataclass
class Record:
    key: str
    raw: dict
    ids: list[str] = field(default_factory=list)
    title: str | None = None
    description: str | None = None
    published: str | None = None
    discovered: str | None = None
    state: str | None = None
    facts: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    sealed: bool = False
    create: bool = True
    url: str = ""

    def validate(self):
        if not self.key or len(self.key) > 200:
            raise ValueError("Invalid record key")
        if any(ord(c) < 32 for c in self.key):
            raise ValueError("Control characters forbidden in record keys")
        # PostgreSQL text cannot represent NUL or isolated Unicode surrogates.
        # Escape canonical display text; original source JSON remains preserved.
        for name in ("title", "description", "published", "discovered", "state"):
            value = getattr(self, name)
            if value is not None:
                value = re.sub(
                    r"[\x00\ud800-\udfff]", lambda m: f"\\u{ord(m.group()):04x}", value
                )
                setattr(self, name, value)
        self.ids = list(dict.fromkeys(identifier(x)[0] for x in self.ids))
        for fact in self.facts.get("attribution", []):
            if fact.get("category") not in CATEGORIES:
                raise ValueError("Invalid attribution category")
            if fact.get("category") in {"autonomous", "human_assisted"} and not (
                fact.get("evidence_url") and fact.get("claim")
            ):
                raise ValueError("Confirmed attribution needs evidence")
        return self


def credits_claim(text, url, published=None):
    """Affiliation alone cannot establish AI use. No keyword promotion to autonomy."""
    found = []
    for token, org in ORGANIZATIONS.items():
        if token in text.lower() and org not in [r["organization"] for r in found]:
            found.append(
                {
                    "organization": org,
                    "model": None,
                    "category": "credited_only",
                    "verification": "requires_review",
                    "claim": text,
                    "evidence_url": url,
                    "published": published,
                }
            )
    return found


def cvss_assessments(metrics):
    result = []
    for i, metric in enumerate(metrics or []):
        for name, score in metric.items():
            if name.startswith("cvssV") and isinstance(score, dict):
                number = score.get("baseScore")
                if number is not None and not 0 <= float(number) <= 10:
                    raise ValueError("CVSS outside 0..10")
                result.append(
                    {
                        "key": f"{i}:{name}",
                        "score": number,
                        "severity": str(score.get("baseSeverity", "unknown")).lower(),
                        "vector": score.get("vectorString"),
                        "version": score.get("version"),
                        "assessor": metric.get("source", "CNA"),
                    }
                )
    return result


def priority(row, path):
    rules = yaml.safe_load(path.read_text()) if path.exists() else {}
    cvss, epss = row.get("CVSS Score"), row.get("EPSS Score")
    if row.get("CISA KEV") is True:
        return "P1", "Listed in CISA Known Exploited Vulnerabilities"
    if (
        cvss is not None
        and cvss >= rules.get("p2_cvss", 7)
        and (epss is not None and epss >= rules.get("p2_epss", 0.1))
    ):
        return "P2", "High technical severity and elevated EPSS probability"
    if cvss is not None and cvss >= rules.get("p3_cvss", 4):
        return (
            "P3",
            "Planned remediation based on available CVSS; exploitation/exposure may be unknown",
        )
    return (
        "P4",
        "Lower measured severity or insufficient evidence; pending validation when unscored",
    )
