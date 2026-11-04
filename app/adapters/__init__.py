from app.adapters.sources import Anthropic, CVE, GHSA, KEV, EPSS, Frontier

ADAPTERS = {c.name: c for c in (Anthropic, CVE, GHSA, KEV, EPSS, Frontier)}
