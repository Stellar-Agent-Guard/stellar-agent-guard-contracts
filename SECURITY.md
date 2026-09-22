```markdown
# Security Policy

## Disclaimer — read this first

This contract is **unaudited** and it **gates fund movement**. Unlike read-only
tooling, a bug or a subtle policy-semantics flaw in `__check_auth` can result in
the loss of the funds held by a deployed instance of this contract.

**Do not deploy this contract to mainnet with real funds until it has been
independently audited.** Testnet use only until then. This is a security
contract; assume the worst about the current code.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
privately to the maintainers via Telegram (the ecosystem norm):

- **Telegram**: [t.me/stellar_dev](https://t.me/stellar_dev)

We will acknowledge receipt within 48 hours and work to address the issue
promptly. Please do not disclose the vulnerability publicly until we've had
a chance to address it.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Model (what the contract guarantees — and does not)

Guarded on-chain, inside `__check_auth`, unbypassable by a compromised agent key:

- Per-transaction and rolling-window spend caps
- Recipient / asset allowlists on SAC transfers
- Protocol / function allowlist (default-deny) on all other calls
- Pause switch, admin freeze, dead-man switch (heartbeat + admin-attested reversal)

Not guarded by v1 (documented in SPEC §2 / §10, not hidden):

- Per-call amount/recipient limits on non-SAC protocol calls (v2 item)
- A live attacker who keeps the agent key heartbeating (caps still bind them)
- Admin compromise (admin can rewrite policy/keys/freeze — by design; it still
  cannot move funds)

## Security Posture & SBOM

To ensure transparency and supply-chain integrity, every official release includes a Software Bill of Materials (SBOM) in [CycloneDX](https://cyclonedx.org/) format (`sbom.cdx.json`) attached directly to the GitHub Release. 

### Verifying Components
You can use the SBOM artifact to inspect the exact crates, versions, and dependencies included in the shipped WASM build to verify deployments against known supply-chain vulnerabilities.

### Generating SBOM Locally
We recommend using `cargo-cyclonedx` for local inventory generation. To generate an SBOM for the project locally, run:

```
# Security Policy

## Disclaimer — read this first

This contract is **unaudited** and it **gates fund movement**. Unlike read-only
tooling, a bug or a subtle policy-semantics flaw in `__check_auth` can result in
the loss of the funds held by a deployed instance of this contract.

**Do not deploy this contract to mainnet with real funds until it has been
independently audited.** Testnet use only until then. This is a security
contract; assume the worst about the current code.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
privately to the maintainers via Telegram (the ecosystem norm):

- **Telegram**: [t.me/stellar_dev](https://t.me/stellar_dev)

We will acknowledge receipt within 48 hours and work to address the issue
promptly. Please do not disclose the vulnerability publicly until we've had
a chance to address it.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Model (what the contract guarantees — and does not)

Guarded on-chain, inside `__check_auth`, unbypassable by a compromised agent key:

- Per-transaction and rolling-window spend caps
- Recipient / asset allowlists on SAC transfers
- Protocol / function allowlist (default-deny) on all other calls
- Pause switch, admin freeze, dead-man switch (heartbeat + admin-attested reversal)

Not guarded by v1 (documented in SPEC §2 / §10, not hidden):

- Per-call amount/recipient limits on non-SAC protocol calls (v2 item)
- A live attacker who keeps the agent key heartbeating (caps still bind them)
- Admin compromise (admin can rewrite policy/keys/freeze — by design; it still
  cannot move funds)

## Security Posture & SBOM

To ensure transparency and supply-chain integrity, every official release includes a Software Bill of Materials (SBOM) in [CycloneDX](https://cyclonedx.org/) format (`sbom.cdx.json`) attached directly to the GitHub Release. 

### Verifying Components
You can use the SBOM artifact to inspect the exact crates, versions, and dependencies included in the shipped WASM build to verify deployments against known supply-chain vulnerabilities.

### Generating SBOM Locally
We recommend using `cargo-cyclonedx` for local inventory generation. To generate an SBOM for the project locally, run:

