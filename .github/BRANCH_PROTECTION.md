# `main` branch protection — the `main-protection` ruleset

`main` is protected by a repository **ruleset** named `main-protection`. GitHub
stores rulesets in repository settings, not in the git tree, so this file and
[`rulesets/main-protection.json`](rulesets/main-protection.json) are the
reviewable, in-repo record of what that protection is:

- **`rulesets/main-protection.json`** is an importable ruleset definition that
  matches the live ruleset (GitHub's own export shape, with server-assigned
  fields such as `id` and `created_at` removed).
- **This file** explains what each rule does, why the `ci` job name is
  load-bearing, which parts a maintainer must apply in GitHub settings, and how
  to detect drift.

> **GitHub does not read this directory.** Committing a change to the JSON does
> not change protection. It records intent and makes the intended state
> reviewable; a maintainer still has to apply it (see
> [Applying a change](#applying-a-change-requires-a-maintainer)).

## What is committed vs. what a maintainer applies

| Item | Where it lives | How it changes |
|---|---|---|
| The ruleset definition (`required_status_checks`, `pull_request` rules) | `.github/rulesets/main-protection.json` (committed) | Normal PR review |
| This explanation and the drift-check commands | `.github/BRANCH_PROTECTION.md` (committed) | Normal PR review |
| The **enforced** ruleset on `main` | GitHub repository settings → Rules → Rulesets (not in the repo) | Maintainer with admin access applies the JSON ([below](#applying-a-change-requires-a-maintainer)) |
| The CI job that produces the required `ci` check | `.github/workflows/ci.yml` (committed) | Normal PR review — but see [the rename warning](#why-the-ci-job-name-is-load-bearing) |

A contribution that changes protection is therefore two steps: a PR that edits
the JSON (and this file), then a maintainer applying it. The PR alone is not
protection; the applied ruleset alone is not reviewable. Keep them in step.

## The ruleset as applied

Target: the branch `refs/heads/main` only. Enforcement: **active**. Bypass
actors: **none** — no user, team, or app is exempt.

| Rule | Parameters | Effect on a PR |
|---|---|---|
| `required_status_checks` | `ci`; `strict_required_status_checks_policy: true`; `do_not_enforce_on_create: true` | The `ci` check must be green, and the branch must be up to date with `main` before merging (a stale branch re-runs checks after update). The check is not enforced when a branch is created. |
| `pull_request` | `required_approving_review_count: 1` | At least one approving review. |
| | `dismiss_stale_reviews_on_push: true` | A new push after approval dismisses that approval — re-approval is required. |
| | `required_reviewers: []`, `require_code_owner_review: false` | No named reviewers or `CODEOWNERS` review are required (there is no `CODEOWNERS` file). |
| | `dismissal_restriction.enabled: false` | No restriction on who may dismiss a review. |
| | `require_last_push_approval: false` | The approver does not have to be the last pusher. |
| | `required_review_thread_resolution: false` | Unresolved review threads do not block merge. |
| | `allowed_merge_methods: [merge, squash, rebase]` | All three merge methods are available. |
| `deletion` | *not present* | **`main` deletion is not blocked.** |
| `non_fast_forward` | *not present* | **Force-push to `main` is not blocked.** |

This describes the ruleset as read from the repository's settings API on
2026-10-20 (`GET /repos/Stellar-Agent-Guard/stellar-agent-guard-contracts/rulesets/<id>`).
Re-check it with the commands in [Detecting drift](#detecting-drift) before
relying on any row above.

### Deliberate omissions, not accidents

The following are **not** enforced today. Each is a maintainer decision, and
changing one is an edit to this file plus the JSON in the same PR:

- No `deletion` rule and no `non_fast_forward` rule. Nothing in the repository
  protects `main` against deletion or a force-push; only the ruleset can.
- Only `ci` is a required check. The other two workflows' jobs —
  `msrv` (the declared minimum toolchain) and `wasm-reproducible` (the
  double-build determinism check, see
  [Reproducible builds](../README.md#reproducible-builds)) — are visible in
  Actions and fail their own jobs, but neither is required to merge. The
  `release` workflow also does not wait on them.
- No code-owner review, no last-push approval, no required thread resolution,
  and no dismissal restriction.

If you want one of these added, open an issue; a maintainer applies the change to
the live ruleset at the same time as the PR that records it.

## Why the `ci` job name is load-bearing

A required status check matches by **exact check-run name**, not by workflow
name, and not by prefix. The ruleset requires the context `ci`, which is the
**job key** in [`.github/workflows/ci.yml`](workflows/ci.yml)
(`jobs.ci`), not the workflow's `name: CI`. The comment above that job says so,
and it is not defensive noise:

- **Rename the job key** (`ci` → `contract-ci`, `build`, anything) and no check
  named `ci` is ever reported. Every PR then shows `ci — Expected — Waiting for
  status to be reported` forever and **nothing can merge**: not contributor PRs,
  not maintainer PRs, not Dependabot PRs. The requirement cannot be satisfied
  and the UI gives no hint that the job was renamed.
- **The rename cannot fix itself through a normal PR.** The PR that renames the
  job runs the renamed workflow from its own head, so its own required `ci`
  check never appears either — it is blocked by the same rule it is changing.
- **Delete the requirement instead of the rename** and the merge gate silently
  disappears: PRs merge with red or missing CI, which is exactly the failure the
  requirement exists to prevent.
- Splitting the job (e.g. `ci-lint`, `ci-test`) has the same effect unless a job
  named exactly `ci` still reports.

If a rename is genuinely required, keep the required context alive in the same
PR:

```yaml
# Keep the required check name stable while the real work moves.
ci:
  needs: [contract-ci]   # the renamed job
  runs-on: ubuntu-latest
  steps:
    - run: echo "required status check shim; real gates run in contract-ci"
```

The shim reports `ci` and inherits the renamed job's result, so protection keeps
working and the ruleset can be updated afterwards (by a maintainer) to require
the new name. Do not merge a job rename without one of these two paths.

## Applying a change (requires a maintainer)

Rulesets need admin access to the repository; contributors cannot apply them.
Two supported paths:

**Import in the browser** — Settings → Rules → Rulesets → **New ruleset** →
**Import a ruleset** → choose `.github/rulesets/main-protection.json`.

**Apply through the API** (same JSON, no retyping):

```bash
# Create it if the ruleset does not exist yet.
gh api --method POST \
  repos/Stellar-Agent-Guard/stellar-agent-guard-contracts/rulesets \
  --input .github/rulesets/main-protection.json

# Or update the existing one in place (ID from the listing command below).
gh api --method PUT \
  repos/Stellar-Agent-Guard/stellar-agent-guard-contracts/rulesets/<id> \
  --input .github/rulesets/main-protection.json
```

After applying, re-run the drift check and, if the API response differs from the
committed JSON (for example because the platform added a field), update the JSON
in a follow-up PR so the record matches reality again.

## Detecting drift

The settings can change without a commit, so compare the live ruleset with the
committed file rather than trusting either alone:

```bash
REPO=Stellar-Agent-Guard/stellar-agent-guard-contracts

# Which rulesets exist, and their IDs.
gh api "repos/$REPO/rulesets" --jq '.[] | "\(.id)\t\(.name)\t\(.enforcement)"'

# The full definition of the main-protection ruleset (drop server-assigned
# fields, restore `bypass_actors`, which the API omits when it is empty, and
# sort keys so the output diffs cleanly against the committed file).
gh api "repos/$REPO/rulesets/<id>" \
  | jq -S 'del(.id, .node_id, .source_type, .source, .created_at, .updated_at,
              ._links, .current_user_can_bypass)
           + {bypass_actors: (.bypass_actors // [])}' \
  > /tmp/live-main-protection.json

jq -S . .github/rulesets/main-protection.json \
  > /tmp/committed-main-protection.json

diff -u /tmp/committed-main-protection.json /tmp/live-main-protection.json
```

An empty diff means the record matches the applied protection. Any difference is
either a settings change that needs recording (PR) or an unintended change that
needs reverting (maintainer).

Rulesets are per repository: a fork has its own (usually empty) ruleset list, so
a contributor's fork will not show these rules. That is expected — the ruleset
governs the upstream repository, and that is where PRs merge.

## What this means for your PR

- The `ci` job must be green **and** the PR branch must be up to date with
  `main`. [CONTRIBUTING.md](../CONTRIBUTING.md#pull-request-process) lists the
  same commands CI runs, so a locally green branch should not surprise you.
- One approving review is required, and pushing after approval dismisses it.
  Ask for re-review when you push.
- Draft PRs are not exempt from the gate, but they are exempt from being merged;
  see the stale policy in [`.github/workflows/stale.yml`](workflows/stale.yml).
