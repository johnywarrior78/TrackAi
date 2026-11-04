# Public source status and use

Validated on 2026-11-03. Public sources can change. A successful HTTP request does not establish full corpus coverage or unrestricted redistribution rights.

| Source | Integration | Validation / limitations |
|---|---|---|
| Anthropic CVD | Directly linked `data/ledger.json` and `data/payload.json`, current and published archives | Real current/May/August snapshots ingested; unknown/unrevealed fields remain unknown; no commitment reversal |
| CVE Program | Official cvelistV5 raw JSON by tracked CVE; optional local corpus scan | Live records enriched; missing public records recorded and retried; full corpus historical scan available locally, not downloaded by default |
| GitHub Advisories | Public REST `GET /advisories?cve_id=...` | Credential-free live requests succeeded; optional token raises quota; checkpoints and retries handle rate limiting; currently enrichment of tracked CVEs/GHSAs, not global discovery |
| CISA KEV | Official cisagov/kev-data public JSON | Live full catalog retrieval; matched/nonmatched states persisted for tracked CVEs; changes retained |
| FIRST EPSS | Public FIRST API, batches of 50 CVEs | Live dated scores stored; missing scores remain unknown; selective history up to 365 days per command; official dated bulk CSV archive automatically used above EPSS_BULK_THRESHOLD, cached once per date |
| Frontier AI CVE Tracker | Discovery connector gated off | Repository metadata has `license: null` and no LICENSE file in its root; content not ingested or redistributed |

Anthropic publishes ledger and payload links from its [CVD dashboard](https://red.anthropic.com/2026/cvd/); the [archive](https://red.anthropic.com/2026/cvd/archive/) links the historical snapshots. Payload `as_of`, manifest identifier and source URLs are retained separately from platform observation timestamps. Individual finding pages sometimes provide model details not present in the current structured ledger; the adapter does not infer those details across the portfolio. Public source statements establish AI use, while autonomous/human-assisted method often remains unspecified.

The Frontier [repository](https://github.com/securin-public/frontier-ai-cve-tracker) currently exposes a README table. Its attribution evidence may guide a human to primary sources, but public visibility alone is not permission to copy/relicense the table. The connector fails explicitly pending content license and schema review. An operator cannot bypass that gate by merely setting a token.

The [CVE data repository](https://github.com/CVEProject/cvelistV5) has its own terms; retain source provenance and review repository terms before redistribution. Organization credit detection is deliberately conservative and does not claim AI was used. Initial monitored credit tokens include Anthropic, OpenAI, Google DeepMind/Big Sleep, Microsoft MDASH and DepthFirst. The [GitHub REST advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories) supports public unauthenticated reads subject to rate limits. GitHub advisory database content and upstream advisory text can have different applicable terms; preserve both provenance and any license notices.

[CISA KEV](https://github.com/cisagov/kev-data) and [FIRST EPSS](https://www.first.org/epss/) remain attributable to their publishers. EPSS is exploitation probability, not technical severity and not proof of active exploitation. Review FIRST's usage/attribution terms before redistributing scores. This project does not relicense intelligence under its application code license.

No arbitrary source URLs are fetched. Adapters use fixed public HTTPS endpoints, and no exploit, attached reproducer, private disclosure, or commitment preimage search is executed. Robots restrictions apply if a future adapter scrapes HTML; these adapters use explicitly linked JSON and documented APIs.

Coverage is incomplete by nature. In particular, the current initial live inventory is Anthropic-ledger based; the other monitored providers do not acquire discoveries automatically without a CVE corpus scan and attribution review. Raw provider counts must not be interpreted as model capability rankings.
