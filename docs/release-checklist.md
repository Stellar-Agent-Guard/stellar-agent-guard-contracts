# Release checklist

Maintainer procedure for cutting a contract release (`v*` tag) of
`stellar-agent-guard-contracts`. It exists so that everything a release asserts —
the crate version, the SPEC revision, the verification scope, and the published
artifacts — moves together instead of drifting between PRs.

The workflow itself lives in [`.github/workflows/release.yml`](../.github/workflows/release.yml);
this page is the human checklist around it. Release provenance is tracked by
[issue #73](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/73).

## Before you start

- [ ] The release's behavioral change is already merged to `main`; releases do not
      carry unmerged work.
- [ ] The required `ci` check is green on the commit you are about to tag, and the
      `msrv` and `wasm-reproducible` jobs are green on it too.
- [ ] No open PR is intended for this release and still in flight.

## 1. Version and SPEC revision

- [ ] Bump `version` in [`Cargo.toml`](../Cargo.toml). The release tag is
      `v<crate version>` — [`scripts/verify-release-version.sh`](../scripts/verify-release-version.sh)
      fails the release when the tag and `Cargo.toml` disagree.
- [ ] **Update the SPEC revision** in [`SPEC.md`](../SPEC.md#specification-revisions):
      - replace the header line's `rN — unreleased` with `rN — vX.Y.Z`, naming the
        tag you are about to push;
      - update that revision's row in the revision table so the `Contract release`
        column names `vX.Y.Z` and the `Git revision` column names the commit being
        tagged.
- [ ] If the release contains normative changes made since the last revision, bump
      the revision label (`rN` → `rN+1`) in the same PR that carries the change,
      not at tag time. A release never introduces a revision that no merged PR
      described.
- [ ] Do not claim a revision is released before the tag exists. If the tag is
      deleted or the release is abandoned, revert the SPEC line to `unreleased`.

## 2. Verification scope

- [ ] Update [`SECURITY.md` § Verified against](../SECURITY.md#verified-against)
      for the protocol, `soroban-sdk`, and Rust toolchain the release was built
      and verified on. If a protocol or SDK change has not been re-verified, mark
      that section **STALE** here and in the release notes rather than leaving the
      old version named as verified.
- [ ] Confirm the fixture network fields in
      [`tests/fixtures/index.json`](../tests/fixtures/index.json) match the
      protocol and date the evidence was recorded on, and that
      [`tests/fixtures/README.md`](../tests/fixtures/README.md) still narrates the
      same run.
- [ ] If fixtures were re-recorded, run the local fixture gate
      (`cargo test`) and make sure scenarios/scenario count and the machine index
      agree.
- [ ] If live re-verification applies to this release, follow
      [`docs/fixture-verification.md`](fixture-verification.md). A claim the script
      reports as *indeterminate* or *not remotely verifiable* is not a release
      blocker by itself, but it must not be described as verified in the release
      notes.

## 3. Documentation consistency

- [ ] [`docs/README.md`](README.md)'s SPEC ↔ GitBook cross-reference map still
      covers every SPEC section, including any section added in this release.
- [ ] [`docs/SUMMARY.md`](SUMMARY.md) lists any page added under `docs/`
      (`scripts/verify-docs-reachability.sh` enforces this in `ci`).
- [ ] [`docs/audit-pack.md`](audit-pack.md) status rows reflect what this release
      actually closed.
- [ ] The reason-symbol vocabulary is unchanged, or any addition is documented in
      SPEC §9.1 and [`docs/reason-glossary.md`](reason-glossary.md) as additive.

## 4. Tag and publish

- [ ] Run the local gate documented in [`CONTRIBUTING.md`](../CONTRIBUTING.md) on
      the release commit.
- [ ] Tag and push:

  ```bash
  git tag vX.Y.Z
  git push origin vX.Y.Z
  ```

- [ ] The `gates` job re-runs format, clippy, and tests; a failed gate blocks
      release creation.
- [ ] Confirm the release publishes all four assets: the WASM, its `.sha256`,
      `provenance.txt`, and `sbom.cdx.json`.
- [ ] Confirm `provenance.txt` names the tag, the commit, and the pinned toolchain.

## 5. After publishing

- [ ] Confirm the GitBook site imported the release commit (Git Sync follows the
      connected branch) and that `SPEC.md` renders with the released revision
      line.
- [ ] Note the SPEC revision in the release notes so an auditor reading an
      artifact can match tag → revision without opening the repository.
- [ ] If a coordination issue exists for release automation, record the release
      there; this checklist is the manual procedure the automation must reproduce.
