# Threat model and deployment security

Trust boundaries: untrusted public source responses -> normalized records -> SQLAlchemy -> PostgreSQL -> Streamlit/Excel. Local operators and deployment environment are trusted; public feeds, links and descriptions are not.

Controls implemented:

- Parameterized SQLAlchemy statements; identifier validation and probability bounds; unknown values retained as null.
- Fixed outbound public HTTPS allowlist, no URL credentials or nonstandard ports, public-IP DNS validation, no redirects, connection pooling, bounded expanded JSON bytes, request pacing/timeouts/retries. Source text never controls an outbound request.
- TLS certificate verification enabled, environment proxy inheritance disabled. Optional GitHub authorization is sent only to api.github.com. HTTP status logging omits request headers and source exception detail; configuration secrets are not printed.
- Source text rendered through Streamlit text/JSON/dataframe widgets, with no unsafe HTML. Source URLs stored as evidence are not automatically fetched.
- XLSX cells explicitly typed as text, formula-like prefixes neutralized, only HTTP(S) hyperlinks. CSV exports use the same neutralizer.
- No automatic exploit, reproducer, code snippet, shell command, or private attachment execution. No scraping behind authentication, no attempt to reverse commitments.
- Nonroot app container with dropped capabilities/no-new-privileges; internal-only database port; loopback host dashboard port; owner-only report files and private directories on first creation.

Operational responsibilities and limits:

Streamlit has no application authentication or RBAC in this release. For multiuser access place it behind an authenticated reverse proxy (for example Caddy with TLS and an open-source OIDC proxy such as oauth2-proxy). Bind dashboard service to a private network, restrict direct port access and configure trusted proxy/cookie/TLS settings. Set the Streamlit cookie secret from an environment variable if operating multiple replicas. Do not disable CORS/XSRF protections. Dashboard report generation writes shared artifacts; isolate users if write access must be restricted.

Use least-privilege PostgreSQL credentials and TLS where database traffic crosses hosts. Compose's initial database account is an owner for convenient local setup, not a separated migration/runtime role. Keep secrets out of images, version control, reports and CLI history; `.env` is ignored but operator permissions matter. Public responses may include personal credit information; apply your retention policy.

DNS allowlisting/validation is defense in depth, not DNS pinning; enforce egress restrictions at the host/network layer in hostile DNS environments. JSON facts are adapter-validated rather than full upstream-schema validation. Malformed pages fail atomically for operator review. There is no malware scan of stored text because no downloaded content is executed. Audit and update dependencies with `uv run pip-audit`, rerun tests, and regenerate `uv.lock` in a reviewed update. A clean advisory audit is a point-in-time check, not a security guarantee.
