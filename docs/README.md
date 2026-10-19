# Documentation site — how it is built, previewed, and published

The published documentation for this repository is a **GitBook site**:

<https://soroban-cost-estimator.gitbook.io/stellar-agent-guard-contracts/>

This page is for contributors who change documentation. It answers four
questions that are otherwise only discoverable by reading
[`gitbook-docs.yaml`](../gitbook-docs.yaml) and guessing: what is synced, what
triggers a sync, how to preview a change, and who can publish it. It also
states which file actually controls navigation, because two files look like
they do.

## What is synced (the source directory)

**There is no separate content folder and no build step in this repository.**
GitBook's Git Sync imports Markdown straight from the repository; the only
repo-side configuration is [`gitbook-docs.yaml`](../gitbook-docs.yaml) at the
repository root.

The mapping in that file is the authority for *which directory feeds which
GitBook space*:

| GitBook section | Space | `content.directory` | Repository path |
|---|---|---|---|
| Learn | Getting Started (default) | `./` | repository root |
| Learn | Concepts | `./concepts` | **does not exist** (the pages live in `docs/concepts/`) |
| Learn | Functions | `./functions` | **does not exist** (the pages live in `docs/functions/`) |

Two consequences worth knowing before you move a file:

- The **Getting Started** space imports the repository root recursively: the
  root `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `SPEC.md`, the pages under
  `docs/`, and `tests/fixtures/README.md` are all published from that one space
  (the live site's `llms.txt` lists exactly that tree). Adding a Markdown file
  under a mapped directory therefore adds a page to the published site unless
  GitBook is configured to ignore it.
- The **Concepts** and **Functions** spaces currently sync from
  `./concepts` and `./functions` at the repository root, which do not exist
  there; their pages are only reachable through the Getting Started space at
  `docs/concepts/...` and `docs/functions/...`. As of 2026-10-19 those two
  spaces are empty. If the intent is for them to hold the pages, the fix is a
  one-line change per entry (`./concepts` → `./docs/concepts`,
  `./functions` → `./docs/functions`) done deliberately by a maintainer,
  because it changes published URLs and duplicates pages across spaces.
  Documenting the current behaviour here is not an endorsement of it.

## Navigation: `gitbook-docs.yaml` vs `docs/SUMMARY.md`

Both files matter, at different levels. Neither silently overrides the other.

1. **[`gitbook-docs.yaml`](../gitbook-docs.yaml) wins for site structure.** It
   defines the sections, the spaces, each space's `path` (URL prefix), the
   default landing space, and each space's source directory. A space's `key`
   (`space-getting-started`, `space-concepts`, `space-functions`) is its
   permanent identity: renaming a `key` makes GitBook create a *new* space and
   leave the old one detached, breaking links and losing GitBook-only content.
   Change `title` to rename a space; change `path` to change its URL. Never
   edit an existing `key` casually.
2. **[`docs/SUMMARY.md`](SUMMARY.md) controls nothing on the GitBook site
   today.** GitBook reads `SUMMARY.md` from the *root of the mapped space
   directory*. The Getting Started space maps to the repository root, and there
   is no `SUMMARY.md` there — the only one lives at `docs/SUMMARY.md`, one
   level below the space root. GitBook therefore **infers the sidebar from the
   folder and file layout**, and publishes `docs/SUMMARY.md` as an ordinary
   page. You can verify this against the live site: its page order follows the
   repository tree, not the order in `docs/SUMMARY.md`.
3. **`docs/SUMMARY.md` still matters in the repository.** It is the intended
   table of contents on GitHub, and
   [`scripts/verify-docs-reachability.sh`](../scripts/verify-docs-reachability.sh)
   fails CI when a Markdown file under `docs/` is neither linked from it nor
   listed in [`docs/.summary-allowlist`](.summary-allowlist). CI also fails
   when a `SUMMARY.md` link points at a file that does not exist.

If the project later wants `SUMMARY.md` to drive the published sidebar, the
change is to add a `SUMMARY.md` at the repository root (the space root) — a
site-structure decision, not a documentation edit. Until then, treat the
GitBook sidebar as generated and keep `docs/SUMMARY.md` correct for the repo
check and for GitHub readers.

## What triggers a sync

There is **no GitHub Actions workflow that builds or deploys the docs site**.
Publication is handled entirely by GitBook's Git Sync integration, which is
configured in the GitBook app — repository, branch, project directory, and sync
direction are stored there, not in this repository. `gitbook-docs.yaml` is the
only sync configuration under version control.

In practice:

- A **push to the branch connected in GitBook** is picked up by GitBook and
  imported. That branch is expected to be `main`; confirm it in GitBook's Git
  Sync settings rather than assuming, because the repository cannot show it.
  This means a documentation change is live only after its PR merges.
- Edits made **in the GitBook editor** are committed back to the connected
  branch by GitBook, so they arrive as ordinary commits. If GitBook is ever
  configured one-way (GitHub → GitBook), editor changes do not come back and
  must be made in the repository instead.
- `gitbook-docs.yaml` is written/updated by GitBook when a maintainer saves the
  site's content mapping; hand-edits are allowed but should be reviewed like
  code, because a wrong `directory` silently empties or duplicates a space.

## Local preview

There is no local GitBook renderer configured in this repository, so a preview
has two parts:

1. **Prose and Markdown (always available).** Render the file in your editor or
   on GitHub and check links, tables, and code fences. Run the repository's
   own gate as well:

   ```bash
   scripts/verify-docs-reachability.sh
   ```

   This proves every `docs/` page is reachable from `docs/SUMMARY.md` (or
   explicitly allowlisted) and that every `SUMMARY.md` link resolves.
2. **Site layout (GitBook account required).** Open a pull request against the
   synced branch. GitBook's GitHub app attaches a **preview status with a
   unique URL** to that PR, rendering the change in the real site layout before
   merge. Preview URLs are served from the published site and are only
   accessible to signed-in GitBook users. **PRs opened from forks do not get a
   preview by default** (a security default, configurable by a maintainer in
   Git Sync settings), so a fork contributor should rely on Markdown preview
   plus maintainer review, and a maintainer can trigger the preview from a
   branch in this repository when layout matters.

Treat a layout-sensitive change (new page in navigation, moved directory,
`gitbook-docs.yaml` edit) as unverified until it has been seen through the PR
preview or the GitBook editor.

## Who can publish

- **Contributors** publish by opening a PR; the change goes live when it merges
  to the connected branch. No GitBook account is needed to write, only to open
  a preview URL.
- **Maintainers with access to the GitBook site** can publish directly from the
  GitBook editor and can change the site mapping (`gitbook-docs.yaml`). Only
  they can configure Git Sync, enable fork previews, or change the connected
  branch.
- The repository's normal review rules apply to documentation like any other
  change: a green `ci` check and an approving review before merge.

## Checklist for a documentation change

1. Edit the Markdown under `docs/` (or the root files the space publishes).
2. If you add, rename, or remove a page under `docs/`, update
   [`docs/SUMMARY.md`](SUMMARY.md) in the same PR — or add the file to
   [`docs/.summary-allowlist`](.summary-allowlist) with a rationale if it is
   intentionally not in the sidebar.
3. Do not change an existing space `key` in `gitbook-docs.yaml`. Change
   `title`/`path` instead, and treat a `content.directory` change as a
   site-structure change that needs a maintainer's review.
4. Run `scripts/verify-docs-reachability.sh`.
5. Open the PR, check the GitBook preview status if it appears, and merge to
   publish.

Cross-references: contributor setup and the rest of the gate live in
[CONTRIBUTING.md](../CONTRIBUTING.md); the on-chain evidence pages are indexed
in [`tests/fixtures/README.md`](../tests/fixtures/README.md); the security
model's version scope is in [SECURITY.md § Verified against](../SECURITY.md#verified-against).
