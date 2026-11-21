# Stellar Agent Guard Contracts

Production-grade Soroban smart contract framework for fine-grained, policy-enforced agent delegation.

## Features
- Custom account integration with Ed25519 signature verification.
- Flexible policy configuration (`set_policy`, asset caps, protocol rules, recipient allowlists).
- Dead-man switch (DMS) liveness check and automatic lazy freezing.
- Two-step admin rotation and administrative freeze/unfreeze controls.

## `set_policy` & Dead-Man Switch Re-Arming
Installing or replacing a policy via `set_policy` re-arms the dead-man clock (`LastHeartbeat = now`) as a side effect. The admin's action counts as a liveness attestation. By contrast, `revoke_policy` removes the policy but leaves `LastHeartbeat` unchanged.

## Local Development & Testing
```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```
