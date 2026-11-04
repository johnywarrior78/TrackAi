# Troubleshooting

**Dashboard says initialize database:** run `aivi init-db` from the project root with the same DATABASE_URL/environment as the dashboard. SQLite relative paths resolve from the working directory.

**Source partial/failure:** inspect Source Health and structured `logs/aivi.log`. Successful pages are already stored; rerun just the failed source. Upstream schema changes deliberately fail rather than invent compatibility. A failed page leaves its checkpoint unchanged.

**CVE record unavailable:** assignment can precede publication or an identifier can be erroneous. The adapter stores `availability.public_record=false`, advances to other records and revisits on the next completed sweep. This is not confirmation that the identifier is rejected. A genuine rejected CVE retains its official state.

**GitHub 403/429:** quota may be shared by IP. Retries are capped and source checkpoints remain resumable. Wait for reset or configure an optional GITHUB_TOKEN. Frontier's disabled ingestion is a licensing gate, not a token problem.

**Unknown fields or no EPSS:** upstream may not publish that value; null does not mean zero. Ledger `patched=false` is treated as unconfirmed patch availability, not proof that no patch exists. Conflicting severities are available on the details page.

**Empty New Vulnerabilities:** first successful workbook is a baseline; subsequent successful daily reports only include observations after the preceding report cutoff. Use inventory sheets or a custom export for historical inventory.

**Job already running:** another process owns the database lock. PostgreSQL releases it on disconnect. SQLite is evaluation only; see the documented stale-lock recovery procedure after verifying process termination.

**No observations before installation:** expected. Archived source snapshot dates are preserved separately; the application does not fabricate historical first-seen dates or daily aggregates.

**Report fails on disk/database error:** previous successful reporting cutoff is unchanged. Free disk/restore connectivity and retry. Report history records failure status. Long text and row-limit splitting are handled automatically.

**Python version mismatch:** use 3.12+. `uv sync --python 3.12 --frozen --extra dev` can obtain a supported interpreter where allowed. The implementation's validation used 3.12.12. Temporary test environments are not a substitute for installing a persistent runtime or using Compose.

**macOS Python points into `/tmp`, or the project was moved:** stop the running dashboard/worker and rerun `./scripts/setup_macos.sh`. It recreates `.venv` using Python under the project's persistent `.python` directory. Existing data/configuration remains in place. For dependency tools and tests, use `--dev`.

**Finder launches from the wrong directory:** double-click `Start Dashboard.command`, or use the absolute path to `scripts/aivi`. Both launchers anchor configuration/data paths to the project. No environment activation is required.

**Dashboard port occupied:** use `./scripts/aivi dashboard --port 8502` and open `http://127.0.0.1:8502`.
