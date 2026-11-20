# Stellar Agent Guard Contracts

Smart contract guardian for autonomous agents on Soroban / Stellar.

## Overview

`stellar-agent-guard-contracts` provides a custom Soroban account implementation that guards autonomous agents against runaway spend, unauthorized contract interactions, and abandoned state.

### Key Features

- **Spend Caps**: Per-transaction limits and rolling time-window budget caps.
- **Allowlists**: Restricted token assets, protocol contract calls, and recipient addresses.
- **Dead-Man Switch (DMS)**: Automatic lazy freeze if the agent stops sending heartbeats within the grace period.
- **Kill Switch**: Instant admin freeze and resume controls.
- **Two-Step Admin Rotation**: Secure handover protocol for admin keys.

---

## Core Functions

- `set_policy(config: PolicyConfig)`: Installs or replaces the spend policy. As a side effect, installing or replacing a policy re-arms the dead-man clock by stamping `LastHeartbeat = now`, treating the admin's action as a liveness attestation. (Note: `revoke_policy` removes the policy but leaves `LastHeartbeat` untouched and does not re-arm the clock.)
- `heartbeat()`: Agent liveness ping. Updates `LastHeartbeat = now`.
- `freeze()` / `unfreeze()`: Admin kill switch and reversal path.
- `status()`: Read-only health and gate status check.

---

## Building and Testing

Prerequisites: Rust toolchain with Soroban target (`wasm32-unknown-unknown`).

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

## License

Licensed under Apache 2.0.
