Closes #413

## Summary

Replace inline agent-secret placeholders in README command examples with hidden
`AGENT_SECRET` prompts, and document the safe environment-variable form in the
fixture and `agent-tx` guides. The prompts keep secrets out of shell history.

## Verification

- `./scripts/verify-docs-reachability.sh` (passed)
- `./scripts/verify-readme.sh` (could not complete: Cargo and the WASM artifact are unavailable)
