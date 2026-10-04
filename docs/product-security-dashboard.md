# Product Security Dashboard

Open **Products**, select a product, then use the chart icon beside **Compare
releases**. The same icon on a release opens a release-filtered view. On the
Products screen it opens the portfolio overview.

## What the Numbers Mean

- Counts use the latest completed, saved report per model workspace, not every historical revision.
- A finding in two releases or two models is two **occurrences**. Full-release and application-model overlap is disclosed, not silently deduplicated by title.
- Open risks include Pending review, In review, Action required, and Mitigation proposed. Validation questions have their own count.
- Only **Verified fixed** counts as fixed. Accepted risk and False positive remain separate review outcomes.
- Severity percentages use the open-risk count under the selected filters. Review-status percentages use all matching findings, including questions. An empty denominator is N/A.
- Confirmed and Potential are the tool's evidence classifications, not proof that a deployed vulnerability was reproduced.
- A failed or running job leaves the last completed report in view. Its attempt state is shown separately. A newer quality-blocked completed report remains visible as preliminary; it is not silently replaced by an older ready report.
- Drafts and cloned models with no new report do not increase completed coverage.
- Application totals count registered application IDs. A release with one assessed application is not automatically a completely assessed release. Per-release application inventory is not yet defined, so the dashboard does not invent a complete-release coverage percentage.
- Legacy/unverified reports without an authoritative server association are counted separately and excluded from risk totals. Reanalyze those models through the governed workflow after reviewing their inputs. No automatic migration fabricates missing evidence.

## Working With Findings

The dashboard has Overview, Risks, Coverage, and History views. Overview keeps
the key risk totals and charts together; selecting a severity or review status
opens the matching risk register. Coverage contains assessment counts and models.
History contains the recorded observations and does not use the current filters.

The filter button opens the available controls on both desktop and mobile.
Active filters remain visible when the panel is closed and can be removed
individually or reset together. Search stays visible; typing is debounced and
superseded requests are cancelled. The report risk register and architecture
flow list use the same collapsible-filter pattern.

Filter by release, application, environment, model scope, evidence tier, report
quality, severity, review status, finding type, or search text. Charts also act
as filters. Application/release coverage follows model-scope filters; finding
filters do not change whether a model was completed.

Open a finding's detail icon to inspect evidence, DFD flow references,
remediation, and review history. Existing review permissions apply. Saving a
review refreshes the dashboard totals. **Open report revision** opens the exact
revision, and **Back to dashboard** restores the filters. Browser Back works too.

CSV export uses the complete filtered population, not just the visible page.
Paging and export check a snapshot token: if reports or reviews changed since
the overview loaded, refresh rather than mix two different states.

## Portfolio and History

The portfolio shows registered products and products with assessed models. A
product dashboard does not present a misleading nested "total products" count.

**Record overview** stores a dated observation of all active releases, independent
of current filters. Editors and administrators can record observations; viewers
can read them. Repeated recording with no data change is idempotent. History is
explicit observations, not a continuous trend or retrospective reconstruction.
A falling risk count is not labeled as verified remediation.

## Operations and Access

Dashboard reads use SQLite read snapshots, without the writer reservation used
by ordinary mutation transactions. The service batches model/report/review
lookups and never invokes an analyzer or ML model. There is no persistent result
cache to serve obsolete review decisions. The frontend cancels superseded
requests and fetches fresh data when entering or refreshing the dashboard.

The database migration adds only `dashboard_observations` and its index; existing
reports remain unchanged. This table can be backed up with the workspace database.
History currently returns the latest 100 recorded observations per product.

Existing viewer/editor/admin roles are installation-wide. Product IDs and
report associations are validated, but this is not per-product team isolation.
Organizations requiring separate team access must add and validate product ACLs
before sharing one instance between those teams.

## Verification

Backend tests: `backend/tests/test_product_dashboard.py`, alongside existing
product-registry and assessment-workflow tests. The scale fixture contains
50,000 findings across 100 releases. The initial local run returned a roughly
100 KB paginated response in 0.44-0.45 seconds across three samples; this is a
synthetic developer-laptop measurement, not a production SLA or concurrency test.

Frontend navigation helpers are tested in `scripts/product-dashboard.test.mjs`.
Filter controls, dashboard drilldown, view changes, pagination reset and search
debouncing are covered in `scripts/filter-workspaces.test.mjs`.
Browser verification is in `scripts/verify-product-dashboard.mjs`. It targets the
ephemeral `backend/tests/dashboard_fixture_app.py` server on port 8011, never the
user's workspace database, and verifies review refresh, role behavior, CSV,
navigation, pagination, light/dark mode, and mobile layout. Set
`PLAYWRIGHT_MODULE` to an installed Playwright module when needed.

Example fixture-server command from `backend/`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn dashboard_fixture_app:app --app-dir tests --host 127.0.0.1 --port 8011
```

Run the browser script against a running frontend. Captures and results go to
`backend/evaluation_reports/product-dashboard/`, which is local generated output.
