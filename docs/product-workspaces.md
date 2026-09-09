# Product workspaces

The home page lists products. Open a product and create or open a release such as
`26.09`. On the release screen, choose **Complete release product** or **Ad hoc
standalone application**. The latter asks for an application name; no separate
product-level application setup is needed. Both scopes can coexist in a release.
Existing browser history remains available under **Unassigned / history**.

A release can hold separate models for multiple applications. Select **Add threat
model** on the release page, or **Add another application** from a saved report.
Each new model has its own draft and report revisions; existing models are not
replaced. **Back to release** returns from intake, review or a report to the same
release. Prepared drafts are saved before leaving and can be reopened from its
model list. A save failure keeps the draft open instead of discarding it.

The product's release table shows its creation date, report/draft status, model
scope and last modeled date. These values come from saved workspaces, not from
application names alone. A saved report does not mean security approval. Existing
creation dates are recovered from audit records where available; missing dates
are shown as **Not recorded**, not guessed.

Names are normalized for whitespace, Unicode and case. `OPTIMA`, `Optima` and
` optima ` reserve the same product name. Application and release names are unique
within their product. Archiving a product retains its name and history.
An ad hoc application name reuses the same normalized identity within a product,
so its models can still be compared across releases. Existing models are retained.

Product drafts, source text, report revisions and review annotations are stored in
`backend/data/workspaces.sqlite3`, with a browser copy for recovery. Set
`AEGIS_WORKSPACE_DB` to use another SQLite file. Protect and back up that file;
it contains architecture information and is not encrypted by this application.
Stop the app before copying the database, or use SQLite's online backup API.

Reports are immutable. Saving a stale workspace returns a conflict instead of
overwriting a newer copy. The conflict banner pauses sync and offers to export
the local draft before loading the latest server copy.
Cloning a release copies its sources and model draft,
clears report revisions and answers, and requires review for the new release.
Comparison requires the same product, application and environment. It shows
component, flow, boundary and finding changes between explicit report revisions.
"No longer reported" never means a vulnerability was verified fixed.

## Access

Without configuration, the registry accepts local development clients only.
Before shared deployment, configure HTTPS, the existing production API settings,
and `AEGIS_WORKSPACE_TOKENS` as a JSON object mapping operator-provided tokens to
identities: each identity has a unique `name` and a `role` of `viewer`, `editor`
or `admin`. Enter an existing token using **Workspace access** in the UI.
Tokens are kept in session storage and must not be committed to Git.

Viewers can read and compare. Editors can create products, releases and models.
Admins can also rename/archive products and read `/enterprise/audit`. These are
installation-wide roles, not per-product tenant isolation or enterprise SSO.

## Jobs and review

Reviewed analyses run as durable jobs with a bounded queue and one background
worker per application process. Completed results survive browser reloads.
An interrupted worker is detected after its lease expires. Reopen the saved draft
and select **Analyze reviewed model** to resume its job or retry the saved input.
This is not a live deployment scan.

The review's **Workflows** tab records affected components, business invariants
and control-specific owner evidence. Unknown states stay unknown. A declared
absence without evidence does not become a confirmed finding.

The assurance view and exports include declared source issue dispositions.
Cloud policy evaluations are a deliberately bounded IAM subset: unsupported
conditions, variables or policy interactions return unknown. They do not prove
effective deployed permissions. See the [AWS evaluation rules](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).

Automated tests validate implementation contracts, not independent security
accuracy. SLM candidates still cannot publish confirmed findings; promotion
requires reviewed holdout data through the existing evaluation gate.
