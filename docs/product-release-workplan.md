# Product and release management workplan

Status: Saved for future implementation. No feature implementation is authorized
by saving this document. Resume when the user requests it.

## Objective

Make Products the application's home page. Users can create products, manage
their applications or subproducts, add releases, run threat models within a
release, and compare architecture and findings between two releases.

Example: OPTIMA has monthly releases 26.01 and 26.02, each containing a complete
product model and application-specific models.

```text
Products
└── OPTIMA
    ├── 26.01
    │   ├── Complete product threat model
    │   ├── Customer Portal
    │   ├── Payment Service
    │   └── Admin Application
    └── 26.02
        ├── Complete product threat model
        ├── Customer Portal
        ├── Payment Service
        └── Admin Application
```

A release is a software version, such as 26.02. A report revision is another
analysis of the same release after correcting inputs or adding evidence.

## User workflow

### 1. Products home page

- Open the app to a searchable product table.
- Show product name, owner, latest release, assessment status and last update.
- Provide Create product and a rename/archive action menu.
- Clicking OPTIMA opens its releases.

### 2. Product page

- List releases with their labels, dates, assessment status and confirmed
  critical/high finding counts.
- Provide Create release, Manage applications and Compare releases.
- Applications belong to the product and retain their identity across releases.
- Users can also create an application while working inside a release.

### 3. Create a release

- Enter a release label, date and description.
- Choose Start empty or Start from an existing release.
- Starting 26.02 from 26.01 copies architecture, application scope and source
  material into a new draft while preserving component identities.
- Previous reports remain unchanged. Carried evidence and reviewer decisions
  show where review is needed before reuse.

### 4. Release workspace

- Use breadcrumbs such as Products / OPTIMA / 26.02.
- Let users select the complete product or a particular application.
- Reuse the existing workflow: inputs, architecture review, clarifications,
  analysis, then a saved report revision.
- Include shared infrastructure and connections between applications in the
  complete-product model. Do not generate it by merely joining application
  reports, which would miss threats across those connections.

### 5. Compare releases

Select a baseline release and target release, then select a specific report
revision from each. Compare equivalent scopes: complete product against complete
product, or the same application and environment across releases.

| Area | Comparison output |
| --- | --- |
| Architecture | Added, removed, renamed and changed components |
| Connections | Changed endpoints, protocols, data classifications and trust boundaries |
| Controls | Added, removed, changed and still-unknown controls |
| Findings | New, persistent, changed severity, returned and no longer reported |
| Evidence | Changed files, assumptions, clarification answers and reviewer decisions |

Provide Summary, Architecture, Findings and Evidence tabs. Show synchronized
architecture diagrams with changes highlighted. Finding rows open the existing
detail dialog. Allow comparison export.

A missing finding remains labelled "No longer reported" until remediation is
supported by evidence. Record engine and knowledge-base versions and identify
version changes that may explain differences in the results.

### 6. Duplicate prevention

- Normalize names by trimming surrounding spaces, collapsing repeated spaces
  and comparing without case sensitivity.
- Treat OPTIMA, Optima and " optima " as the same product.
- Product names are unique across this installation.
- Release labels are unique within a product.
- Application names are unique within a product.
- Archived names remain reserved; offer restoration of the existing entry.
- Validate in the UI and enforce uniqueness in the backend database, including
  simultaneous creation requests.

Reference: [SQLite unique indexes](https://www.sqlite.org/lang_createindex.html).

## Implementation sequence

- [ ] Persistent storage: add Products, Applications, Releases, release application
  membership and links to analysis workspaces. Use backend SQLite initially;
  browser storage becomes a draft cache.
- [ ] Navigation: add the Products home page, product release list, release
  workspace, breadcrumbs and creation forms.
- [ ] Analysis integration: attach each workspace to its product, release,
  application scope and environment. Add release cloning and preserve report
  revisions and reviewer annotations.
- [ ] Existing-data migration: retain current analyses in an Unassigned analyses
  area so users can organize them without losing reports or source material.
- [ ] Reliable comparison: replace title-based matching with stable component
  identities and finding identities based on rule, affected element and weakness.
  Allow explicit mapping when a rename is ambiguous.
- [ ] Comparison UI and export: implement the four comparison tabs, synchronized
  diagrams and finding details.
- [ ] Verification: test duplicate creation, release cloning, preserved history,
  scope isolation, architecture changes, finding changes and comparison exports.

## Existing code to reuse

- `src/utils/modelWorkspace.js`: saved drafts, immutable report revisions,
  annotation keys and revision comparison.
- `src/components/AnalysisHistory.jsx`: current history and comparison UI. Its
  comparison currently matches finding titles and must be replaced for releases.
- `src/App.jsx`: navigation, analysis creation, history loading and review state.
- `src/components/ModelReviewWorkspace.jsx`: source editing, architecture review
  and clarification workflow.
- `backend/app/services/model_review.py`: preparation and scoped corrections.
- `backend/app/main.py`: review and analysis API endpoints.

Re-read the current code before implementation; other work may change these
modules between saving this plan and resuming it.
