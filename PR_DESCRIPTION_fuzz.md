# Description

Closes #24

This PR adds a fuzzing-style generative test `fuzz_parse_call_against_arbitrary_auth_context_argument_vectors` to `src/engine.rs`.
The test validates that `parse_call` robustly handles dynamically generated, malformed SAC (Stellar Asset Contract) transfer contexts without ever trapping or panicking the host.

### Changes
*   **Tests:** Added `fuzz_parse_call_against_arbitrary_auth_context_argument_vectors` which generates thousands of argument combinations for `transfer` and `transfer_from`.
*   Tested cases include: varying number of arguments (0..4), incorrect types at each position, extra trailing args, and non-address first arguments.
*   Verified that `parse_call` and `decide` gracefully handle every malformed shape by yielding a stable classified denial (e.g., `UnknownContract`) instead of trapping.

### Acceptance Criteria Checklist
- [x] Generator produces contexts for known SAC contracts with: 0..n args, wrong types at each position, extra trailing args, non-address first arg.
- [x] Every case yields a stable classified denial — never a host trap/panic.
- [x] At least one case each for transfer and transfer_from.
- [x] Lint, type-check, and tests all pass locally.
- [x] PR description references this issue with Closes #24.
