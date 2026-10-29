# Documentation Guide & SPEC Cross-Reference Map

This document establishes the relationship between the normative specification ([`SPEC.md`](../SPEC.md)) and the explanatory GitBook documentation site, provides a complete cross-reference map between them, and explains how the documentation site is built, previewed, and published.

## Normative Specification vs. Explanatory Documentation

Stellar Agent Guard maintains an explicit division between normative specifications and explanatory documentation:

- **`SPEC.md` is the NORMATIVE specification** and the single source of truth for contract behavior, authorization placement, storage layout, decision rules, error variants, and architectural invariants. Any behavioral change, new invariant, error variant, or storage layout modification **MUST land in `SPEC.md` regardless** of what is written in the documentation pages.
- **GitBook pages under `docs/` are EXPLANATORY**. They provide high-level architectural overviews, step-by-step developer and operator guides, conceptual walkthroughs, and contributor documentation. Explanatory pages clarify and contextualize normative behavior for human developers, operators, and auditors, but they do not define new contract behavior.

> [!IMPORTANT]
> If any discrepancy exists between `SPEC.md` and pages under `docs/`, **`SPEC.md` always governs**. Contributors modifying contract behavior, state semantics, error codes, or authorization rules must update `SPEC.md` first before updating explanatory documentation.

---

## SPEC ↔ GitBook Cross-Reference Map

The table below maps every section and subsection of [`SPEC.md`](../SPEC.md) to its corresponding GitBook documentation page(s) under `docs/`.

| SPEC Section | GitBook Page(s) | Audience | Status / Notes |
|---|---|---|---|
| [`§1. Mechanism and non-custodial guarantee`](../SPEC.md#1-mechanism-and-non-custodial-guarantee) | [`concepts/custom-account-enforcement.md`](concepts/custom-account-enforcement.md), [`introduction.md`](introduction.md) | Integrators, Operators, Security Architects | **Normative in SPEC.** GitBook pages are explanatory. Details Soroban Custom Account Abstraction, non-custodial custody, and absence of proxy wrappers. |
| [`§1.1. SDK and host surface this is built on (soroban-sdk 27)`](../SPEC.md#11-sdk-and-host-surface-this-is-built-on-soroban-sdk-27) | [`concepts/custom-account-enforcement.md`](concepts/custom-account-enforcement.md), [`functions/check-auth.md`](functions/check-auth.md), [`research/policy-attestation.md`](research/policy-attestation.md), [`research/multi-sig-threshold-models.md`](research/multi-sig-threshold-models.md) | Protocol Engineers, SDK Developers | **Normative in SPEC.** GitBook pages are explanatory; research files are exploratory notes. Defines `CustomAccountInterface`, `__check_auth`, and host auth context structure. |
| [`§2. Enforcement scope — SAC token calls vs. every other Soroban call (REQUIRED FRAMING)`](../SPEC.md#2-enforcement-scope--sac-token-calls-vs-every-other-soroban-call-required-framing) | [`enforcement-scope.md`](enforcement-scope.md), [`concepts/allowlists.md`](concepts/allowlists.md), [`research/non-sac-enforcement.md`](research/non-sac-enforcement.md) | Contributors, Integrators, Security Auditors | **Normative in SPEC** (canonical scope wording). GitBook pages are explanatory. Defines boundary between fully-enforced SAC transfers and default-deny protocol calls. |
| [`§3. Storage model`](../SPEC.md#3-storage-model) | [`architecture.md`](architecture.md#storage-model), [`rent-and-ttl.md`](rent-and-ttl.md) | Protocol Engineers, Operators | **Normative in SPEC.** GitBook pages are explanatory. Specifies instance and persistent storage keys, `PolicyConfig`, and `WindowState` structs. |
| [`§3.1. The window is genuinely rolling — not a fixed bucket`](../SPEC.md#31-the-window-is-genuinely-rolling--not-a-fixed-bucket) | [`concepts/spend-limits.md`](concepts/spend-limits.md#rolling-window-cap) | Integrators, Risk Officers, Operators | **Normative in SPEC.** GitBook page is explanatory. Defines rolling window invariants, ledger time ordering, lazy pruning, same-second coalescing, and conservative 8192-entry merge backstop. |
| [`§3.2. Exact ScVal encoding of PolicyConfig (for non-TypeScript consumers)`](../SPEC.md#32-exact-scval-encoding-of-policyconfig-for-non-typescript-consumers) | [`research/wire-format.md`](research/wire-format.md), [`policy-templates.md`](policy-templates.md) | SDK Developers, Tooling Authors | **Normative in SPEC.** GitBook pages are explanatory. Authoritative `ScVal` types and map order for non-Rust consumers. |
| [`§4. Policy semantics — decision table`](../SPEC.md#4-policy-semantics--decision-table) | [`architecture.md`](architecture.md#decision-table), [`scenario-matrix.md`](scenario-matrix.md) | Protocol Engineers, Contributors, Auditors | **Normative in SPEC** (synchronized with `decision-table.json`). GitBook pages are explanatory. Defines prioritized rules 1–7 executed on each transaction authorization. |
| [`§4.0. Pre-decision authentication and snapshot pipeline (__check_auth)`](../SPEC.md#40-pre-decision-authentication-and-snapshot-pipeline-__check_auth) | [`architecture.md`](architecture.md#pipeline-diagram), [`functions/check-auth.md`](functions/check-auth.md) | Protocol Engineers, Security Auditors | **Normative in SPEC.** GitBook pages are explanatory. Establishes order of execution: signature check, snapshot load, gate checks, and staged window commits. |
| [`§4.1. Gate cost order (measured)`](../SPEC.md#41-gate-cost-order-measured) | [`architecture.md`](architecture.md#account-level-gates) | Protocol Engineers, Performance Auditors | **Normative in SPEC** (raw CPU/RAM benchmarks are normative-only in SPEC). `architecture.md` provides explanatory gate order overview. |
| [`§4.2. Admin freeze and policy pause`](../SPEC.md#42-admin-freeze-and-policy-pause) | [`functions/freeze-unfreeze.md`](functions/freeze-unfreeze.md), [`concepts/dead-man-switch.md`](concepts/dead-man-switch.md#admin-freeze-vs-dead-man-freeze) | Operators, Incident Responders | **Normative in SPEC.** GitBook pages are explanatory. Contrasts immediate admin freeze (`AdminFrozen`) and operational pause (`PolicyConfig.paused`). |
| [`§5. Dead-man switch — precise definition`](../SPEC.md#5-dead-man-switch--precise-definition) | [`concepts/dead-man-switch.md`](concepts/dead-man-switch.md), [`functions/heartbeat.md`](functions/heartbeat.md), [`research/heartbeat-sources.md`](research/heartbeat-sources.md) | Operators, Agent Authors, Integrators | **Normative in SPEC.** GitBook pages are explanatory. Specifies lazy automatic freeze on heartbeat silence exceeding `dms_grace_secs` and `dms_health()` advisory status. |
| [`§5.1. Reversal boundaries — which gate is cleared by what`](../SPEC.md#51-reversal-boundaries--which-gate-is-cleared-by-what) | [`concepts/dead-man-switch.md`](concepts/dead-man-switch.md#reversal-path-admin-only), [`functions/freeze-unfreeze.md`](functions/freeze-unfreeze.md) | Operators, Incident Responders | **Normative in SPEC.** GitBook pages are explanatory. Defines recovery paths: `unfreeze()` for admin freeze and DMS reset; `set_policy` for pause/active window. |
| [`§5.2. When two transaction-level gates fire at once (issue #426)`](../SPEC.md#52-when-two-transaction-level-gates-fire-at-once-issue-426) | [`scenario-matrix.md`](scenario-matrix.md#13-precedence-notes-read-before-trusting-any-single-cell) | Protocol Engineers, Test Authors | **Normative in SPEC.** GitBook page is explanatory. Defines deterministic error precedence when multiple gates are violated simultaneously. |
| [`§6. Per-context classification and rule application`](../SPEC.md#6-per-context-classification-and-rule-application) | [`architecture.md`](architecture.md#4-per-context-classification), [`scenario-matrix.md`](scenario-matrix.md) | Protocol Engineers, Contributors | **Normative in SPEC.** GitBook pages are explanatory. Defines context classification into `ParsedCall` variants and all-or-nothing staged atomic window commits. |
| [`§6.0. Worked example: a mixed multi-context batch (issue #423)`](../SPEC.md#60-worked-example-a-mixed-multi-context-batch-issue-423) | [`architecture.md`](architecture.md#6-all-or-nothing-commit), [`concepts/custom-account-enforcement.md`](concepts/custom-account-enforcement.md#what-this-means-in-practice) | Integrators, Smart Contract Developers | **Normative in SPEC.** GitBook pages are explanatory. Demonstrates atomicity and staged rollback on multi-operation batches. |
| [`§6.1. Self-calls`](../SPEC.md#61-self-calls) | [`functions/heartbeat.md`](functions/heartbeat.md), [`concepts/allowlists.md`](concepts/allowlists.md#self-calls) | Protocol Engineers, Agent Developers | **Normative in SPEC.** GitBook pages are explanatory. Governs that only `heartbeat` is authorized via `__check_auth`; other self-calls fail with `SelfFunctionNotAllowed`. |
| [`§6.2. Asset (SAC) calls — fully enforced`](../SPEC.md#62-asset-sac-calls--fully-enforced) | [`concepts/spend-limits.md`](concepts/spend-limits.md), [`concepts/allowlists.md`](concepts/allowlists.md#tier-1-recipient-allowlist-sac-transfers-only) | Integrators, Operators, Risk Officers | **Normative in SPEC.** GitBook pages are explanatory. Detailed parsing and enforcement rules for SAC `transfer`/`transfer_from`, recipient allowlists/denylists, per-tx caps, and window accounting. |
| [`§6.3. Protocol calls — allowlist only (window/pause state still enforced)`](../SPEC.md#63-protocol-calls--allowlist-only-windowpause-state-still-enforced) | [`concepts/allowlists.md`](concepts/allowlists.md#tier-2-protocolfunction-allowlist-any-call), [`research/non-sac-enforcement.md`](research/non-sac-enforcement.md) | Integrators, Protocol Partners | **Normative in SPEC.** GitBook pages are explanatory. Rules for protocol allowlists, function filtering, and rolling-window call rate limits (`protocol_calls_per_window`). |
| [`§6.4. Anything else — blocked`](../SPEC.md#64-anything-else--blocked) | [`concepts/allowlists.md`](concepts/allowlists.md#create-contract-calls), [`architecture.md`](architecture.md#5-per-kind-enforcement) | Security Auditors, Integrators | **Normative in SPEC.** GitBook pages are explanatory. Fail-closed default-deny: unlisted contracts return `UnknownContract`; contract creation returns `CreateContractNotAllowed`. |
| [`§6.5. Scenario matrix — decision rows × call kinds`](../SPEC.md#65-scenario-matrix--decision-rows--call-kinds) | [`scenario-matrix.md`](scenario-matrix.md) | Contributors, QA Engineers, Auditors | **Normative in SPEC.** `scenario-matrix.md` is the comprehensive explanatory truth table and test coverage mapping. |
| [`§6.6. Admin-rotation errors live outside the per-context path`](../SPEC.md#66-admin-rotation-errors-live-outside-the-per-context-path) | [`functions/admin-rotation.md`](functions/admin-rotation.md), [`key-rotation.md`](key-rotation.md) | Operators, Tooling Authors | **Normative in SPEC.** GitBook pages are explanatory. Clarifies `NoPendingAdmin` error behavior on direct admin invocations. |
| [`§7. Public surface — exact signatures and auth placement`](../SPEC.md#7-public-surface--exact-signatures-and-auth-placement) | [`functions/initialize.md`](functions/initialize.md), [`functions/set-policy.md`](functions/set-policy.md), [`functions/heartbeat.md`](functions/heartbeat.md), [`functions/freeze-unfreeze.md`](functions/freeze-unfreeze.md), [`functions/admin-rotation.md`](functions/admin-rotation.md), [`functions/check-auth.md`](functions/check-auth.md) | Protocol Engineers, Integrators | **Normative in SPEC.** GitBook `functions/` pages are explanatory references. Full specification of ABI, `require_auth` placement, and storage effects. |
| [`§7.1. Error code ↔ CheckResult variant ↔ reason symbol mapping`](../SPEC.md#71-error-code--checkresult-variant--reason-symbol-mapping) | [`reason-glossary.md`](reason-glossary.md), [`contributing.md`](contributing.md#how-to-add-a-new-error-variant-end-to-end) | SDK Developers, Auditors, Operators, Agent Authors | **Normative in SPEC.** `reason-glossary.md` is explanatory guidance per observer role. Maps frozen error codes 1..=33 to error variants, check results, and reason symbols. |
| [`§7.2. Preflight / simulate a transfer (doc alias for check)`](../SPEC.md#72-preflight--simulate-a-transfer-doc-alias-for-check) | [`functions/check-auth.md`](functions/check-auth.md), [`research/wire-format.md`](research/wire-format.md) | SDK Developers, Agent Runtime Authors | **Normative in SPEC.** GitBook pages are explanatory. Specifies permissionless read entrypoint `check()` and `check_detailed()` for preflight simulation. |
| [`§7.3. Policy hash — cheap drift detection (policy_hash)`](../SPEC.md#73-policy-hash--cheap-drift-detection-policy_hash) | [`research/policy-attestation.md`](research/policy-attestation.md), [`functions/set-policy.md`](functions/set-policy.md) | Dashboard Developers, Operators, Auditors | **Normative in SPEC.** GitBook pages are explanatory. Canonical SHA-256 policy digest algorithm for drift detection. |
| [`§8. Config validation (set_policy)`](../SPEC.md#8-config-validation-set_policy) | [`functions/set-policy.md`](functions/set-policy.md), [`policy-templates.md`](policy-templates.md) | Operators, Tooling Authors | **Normative in SPEC.** GitBook pages are explanatory. Authoritative validation rules enforced during `set_policy`. |
| [`§8.1. Identifying the failing rule: validate_policy (issue #35)`](../SPEC.md#81-identifying-the-failing-rule-validate_policy-issue-35) | [`functions/set-policy.md`](functions/set-policy.md) | SDK Developers, Dashboard Authors | **Normative in SPEC.** `functions/set-policy.md` is explanatory. Dry-run validation preflight returning `ValidationOutcome::Invalid(PolicyRuleId)`. |
| [`§9. Events and telemetry`](../SPEC.md#9-events-and-telemetry) | [`architecture.md`](architecture.md#storage-model), [`reason-glossary.md`](reason-glossary.md) | Indexer Developers, Telemetry Engineers, Auditors | **Normative in SPEC.** GitBook pages are explanatory. Specifications of event topics, data payloads, and `PolicyRevision` join keys. |
| [`§9.5. Persistent storage TTL liveness`](../SPEC.md#95-persistent-storage-ttl-liveness) | [`rent-and-ttl.md`](rent-and-ttl.md) | Operators, Infrastructure Engineers | **Normative in SPEC.** `rent-and-ttl.md` is explanatory. Defines write TTL extensions, thresholded read refresh, and restoration semantics. |
| [`§10. Threat model (what this does and does not do)`](../SPEC.md#10-threat-model-what-this-does-and-does-not-do) | [`audit-pack.md`](audit-pack.md), [`faq.md`](faq.md) | Security Auditors, Risk Officers | **Normative in SPEC.** GitBook pages are explanatory. Security invariants: non-custodial custody, unbypassable signature checks, fail-closed design. |
| [`§10.1. Signature binding`](../SPEC.md#101-signature-binding) | [`concepts/custom-account-enforcement.md`](concepts/custom-account-enforcement.md), [`audit-pack.md`](audit-pack.md) | Cryptographers, Security Auditors | **Normative in SPEC.** GitBook pages are explanatory. Cryptographic binding of signature payload to transactions and accounts. |
| [`§10.2. Verification ordering guarantee`](../SPEC.md#102-verification-ordering-guarantee) | [`architecture.md`](architecture.md#1-signature-verification), [`audit-pack.md`](audit-pack.md) | Security Auditors, Protocol Engineers | **Normative in SPEC.** GitBook pages are explanatory. Invariant that signature verification precedes all state reads and policy evaluations. |
| [`§10.3. Availability: a compromised agent key can grief-block its own transactions (issue #424)`](../SPEC.md#103-availability-a-compromised-agent-key-can-grief-block-its-own-transactions-issue-424) | [`audit-pack.md`](audit-pack.md), [`faq.md`](faq.md) | Threat Modelers, Security Auditors, Operators | **Normative in SPEC.** GitBook pages are explanatory. Analysis of agent key griefing vectors and admin mitigation. |
| [`§11. Testnet proof plan (scenarios 1–8: five proven, three planned)`](../SPEC.md#11-testnet-proof-plan-scenarios-18-five-proven-three-planned) | [`verification.md`](verification.md), [`audit-pack.md`](audit-pack.md) | Auditors, Quality Engineers, Community | **Normative in SPEC.** GitBook pages are explanatory evidence records. Eight testnet scenarios and proof fixture links. |

---

### Explanatory GitBook Pages Without Direct SPEC Counterparts

The following GitBook pages provide operational guides, setup procedures, presets, and contributor workflows that do not directly define contract protocol rules. They are **Explanatory-only**; any underlying behavioral change they discuss must land in `SPEC.md`.

| GitBook Page | Audience | Status / Notes |
|---|---|---|
| [`installation.md`](installation.md) | Developers, Operators | **Explanatory-only.** Environment setup, Rust 1.91+ toolchain, `wasm32v1-none` target, and Wasm build instructions. |
| [`policy-templates.md`](policy-templates.md) | Operators, Integrators | **Explanatory-only.** Named starter configurations and presets (day-trader, payments bot, watch-only, max security). Config validation rules are normative in SPEC §8. |
| [`key-rotation.md`](key-rotation.md) | Operators, Incident Responders | **Explanatory-only.** Operational runbook for agent key rotation and two-step admin handover. Rotation mechanics are normative in SPEC §6.6 and §7.2. |
| [`audit-pack.md`](audit-pack.md) | Security Auditors, Protocol Reviewers | **Explanatory-only.** Audit readiness guide, security invariant synthesis, and testnet proof index. Invariants are normative across SPEC §1, §4, §6, and §10. |
| [`contributing.md`](contributing.md) | Contributors | **Explanatory-only.** Development workflows, test running, PR checklist, and step-by-step guide for adding error variants. |
| [`faq.md`](faq.md) | Operators, Integrators, Community | **Explanatory-only.** Frequently asked questions covering account abstraction differences, fee models, and non-custodial guarantees. |
| [`README.md`](README.md) | Contributors, Maintainers | **Explanatory-only.** Guide to the documentation site, GitBook sync, preview workflows, and this cross-reference map. |

---

## Documentation site — how it is built, previewed, and published

The published documentation for this repository is a **GitBook site**:

<https://soroban-cost-estimator.gitbook.io/stellar-agent-guard-contracts/>

This section is for contributors who change documentation. It answers four
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
2. If the change modifies contract behavior or specifications, update `SPEC.md`
   first and update the cross-reference map in [`docs/README.md`](README.md).
3. If you add, rename, or remove a page under `docs/`, update
   [`docs/SUMMARY.md`](SUMMARY.md) in the same PR — or add the file to
   [`docs/.summary-allowlist`](.summary-allowlist) with a rationale if it is
   intentionally not in the sidebar.
4. Do not change an existing space `key` in `gitbook-docs.yaml`. Change
   `title`/`path` instead, and treat a `content.directory` change as a
   site-structure change that needs a maintainer's review.
5. Run `scripts/verify-docs-reachability.sh`.
6. Open the PR, check the GitBook preview status if it appears, and merge to
   publish.

Cross-references: contributor setup and the rest of the gate live in
[CONTRIBUTING.md](../CONTRIBUTING.md); the on-chain evidence pages are indexed
in [`tests/fixtures/README.md`](../tests/fixtures/README.md); the security
model's version scope is in [SECURITY.md § Verified against](../SECURITY.md#verified-against).
