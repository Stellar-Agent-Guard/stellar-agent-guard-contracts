# Security Policy

## Disclaimer — read this first

This contract is **unaudited** and it **gates fund movement**. Unlike read-only
tooling, a bug or a subtle policy-semantics flaw in `__check_auth` can result in
the loss of the funds held by a deployed instance of this contract.

**Do not deploy this contract to mainnet with real funds until it has been
independently audited.** Testnet use only until then. This is a security
contract; assume the worst about the current code.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, report it privately through one of the formal channels below. Do not disclose vulnerabilities publicly or discuss sensitive exploit details in public channels until a fix has been coordinated and published.

### Primary Channel: GitHub Security Advisory (Private Vulnerability Reporting)

Submit a private report via GitHub:
- Navigate to the [New Security Advisory](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/security/advisories/new) page.
- Fill out the advisory form with detailed steps to reproduce, impacted components, and proof of concept.
- This creates an encrypted, private thread visible only to project maintainers.

### Fallback Channel: Direct Email

If GitHub Security Advisories are unavailable or inaccessible, send an email disclosure to the maintainer:
- **Email**: `aigbagbobila34@gmail.com`
- Include `[SECURITY] stellar-agent-guard-contracts vulnerability` in the subject line.
- Provide full reproduction details, affected commit hashes, and potential mitigation strategies.

### Community Channels (Community Discussion Only)

Public communication channels are community-only and are not secure or monitored for confidential disclosures:
- **Telegram**: [t.me/+EzSusj-2vVhhNmI0](https://t.me/+EzSusj-2vVhhNmI0) (Stellar Agent Guard group) or [t.me/stellar_dev](https://t.me/stellar_dev) (Ecosystem channel)
- **Discord**: [Stellar Agent Guard server](https://discord.gg/Z766vsgjg)

Do not submit vulnerability reports, proof of concepts, or sensitive issue details through Telegram or Discord.

### Expected Response Windows

Maintainers commit to the following response timeline:
- **Acknowledgement**: Within 48 hours of initial report receipt.
- **Triage & Assessment**: Within 5 business days, confirming severity and validity.
- **Remediation Updates**: Regular status updates provided at least weekly until an advisory or patch is released.
- **Coordinated Disclosure**: Fixes will be prepared, audited, and published with credit to the reporter upon release.

## Scope

### In-Scope

The following components within this repository are in-scope for security reports:
- Core Soroban smart contract source code (`src/`):
  - `lib.rs`: Contract entrypoint, `__check_auth` authorization gate, lifecycle management, and admin controls.
  - `engine.rs`: Policy decision table, spend cap enforcement (per-transaction, sliding-window), and recipient/asset allowlists.
  - `window.rs`: Rolling spend window tracking, entry coalescence, and lazy pruning.
  - `types.rs`: Storage keys, data structures, and authorization context models.
- Agent transaction sign-and-submit utility (`tools/agent-tx`).

### Out-of-Scope

The following areas are explicitly out-of-scope for this repository:
- **Deployed testnet instances**: Testnet contracts operate with non-production test funds and temporary keys. Operational issues on testnet without underlying contract vulnerabilities are out-of-scope.
- **Sibling repositories**: The following companion repositories maintain their own independent security policies, release cycles, and issue trackers:
  - [`stellar-agent-guard-sdk`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-sdk) (TypeScript / client SDK)
  - [`stellar-agent-guard-dashboard`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-dashboard) (Management UI / frontend)
- **Upstream infrastructure**: Vulnerabilities in Stellar Core, Horizon, Soroban host environment, or Rust compiler targets should be directed to the Stellar Development Foundation or upstream maintainers.

## Bug Bounty Program

**Current Position: None / Not-yet.**

Stellar Agent Guard does not currently operate a paid bug bounty program. The repository is actively targeting independent third-party audits (tracked in issue #6) prior to mainnet deployment. Security researchers and community contributors disclosing valid vulnerabilities will receive public attribution in release notes and GitHub Security Advisory acknowledgments.

## Maintainer Action Item

Repository maintainers must enable private vulnerability reporting in the repository configuration:
- [ ] Enable "Private vulnerability reporting" under [Repository Settings > Security > Code security and analysis](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/settings/security_analysis). This setting allows external researchers to submit advisories privately via the GitHub UI. (This configuration cannot be performed via pull request.)

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

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

## Security Considerations

- The policy admin holds **no fund-moving authority**; only the registered agent
  key moves funds, and only within policy. Losing the admin key means losing the
  ability to change policy or unfreeze — it does not put funds at risk.
- The account is **default-deny**: unlisted contracts and functions are blocked.
  Adding a protocol is an explicit policy act.
- Contract creation by the account is denied in v1.
- Read functions are public (no DoS on reads); policy writes are admin-only.
- This contract is **unaudited**. An audit is a prerequisite for mainnet use;
  track it via the issue backlog.