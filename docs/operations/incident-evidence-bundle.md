# Incident evidence bundle

Incident review goes faster when every responder collects the same evidence in the same shape.
This page defines that shape: one JSON object that answers "which contract, which code, which
policy, which transactions, and which events" **without** carrying anything secret. It is a
*format*, not a tool — the sample below is checked in so a bundle can be produced and reviewed by
hand.

A bundle is safe to attach to a public issue, share with an auditor, or archive next to the
deployment record. It must never contain a secret key, a signed envelope, or a credential.

## Format

One UTF-8 JSON object with `bundle_version: 1`. Unknown fields are ignored by readers; a bundle
missing any required field is invalid.

### Required fields

| Field | Type | Meaning |
|---|---|---|
| `bundle_version` | integer | Always `1` for this layout. Bump only for a breaking change. |
| `incident_id` | string | Stable slug for the incident (`2026-11-25-policy-mismatch`). Never reuse. |
| `created_at` | string | RFC 3339 UTC timestamp of bundle assembly, e.g. `2026-11-25T14:05:00Z`. |
| `network` | object | `{ "name": "testnet", "passphrase": "Test SDF Network ; September 2015" }`. The passphrase is what disambiguates forks and futurenets. |
| `guard_contract_id` | string | The guard's `C...` address. |
| `wasm_sha256` | string | SHA-256 of the deployed WASM (64 lowercase hex), from the release checksum or `sha256sum` of the built artifact. This is **not** the uploaded code hash. |
| `policy_hash` | string | `policy_hash()` at the time of the incident (64 lowercase hex). Pins policy content without shipping the whole config. |
| `policy_revision` | integer | `status().policy_revision` — the join key between policy generations and decisions. |
| `tx_hashes` | array of string | Non-empty list of the incident's transaction hashes (64 lowercase hex), oldest first. Every event's `tx_hash` must appear here. |
| `events` | array of object | The relevant contract events (see below). Empty only when the incident produced no events. |
| `toolchain` | object | `{ "rustc_version": "1.91.0", "stellar_cli_version": "27.1.0", "agent_tx_version": "0.1.0" }`. Exact strings as reported by `--version`. |

Each `events` entry is `{ "tx_hash", "ledger", "contract_id", "topics", "data" }`, where `topics`
is the decoded topic list in order (`topics[0]` is the `event_...` name) and `data` is the decoded
data map. Event names, topics, and data keys are normatively listed in
[SPEC §9.2](../../SPEC.md#92-event-catalogue); copy values verbatim rather than re-deriving them.
Use `null` for an absent value (for example a heartbeat's disabled `expires_at` is `0`, not
`null` — preserve the contract's own value).

### Optional fields

| Field | Type | Meaning |
|---|---|---|
| `title` | string | One-line human summary. |
| `severity` | string | `low`, `medium`, `high`, or `critical`. |
| `summary` | string | Short narrative: what was observed, not what was guessed. |
| `rpc_url` | string | Endpoint used for reads. Strip API keys and tokens from the URL. |
| `ledger_range` | object | `{ "start": <u32>, "end": <u32> }` covering every event ledger. Required in practice when events were gathered with a range query. |
| `status_snapshot` | object | The `status()` read taken at assembly time (admin_frozen, paused, heartbeat_expired, window_remaining, …). |
| `policy` | object | The full `PolicyConfig`, when the incident is about policy content. |
| `agent_fingerprint` | string | `sha256(pubkey)[0..8]` as 16 lowercase hex (the `agent_rotated` form) or the 8-hex `initialized` prefix, labelled accordingly. Prefer this over the full public key. |
| `admin_address` | string | Admin `G...`/`C...` address at the time of the incident. Public, but keep it only if it helps the review. |
| `attachments` | array of object | `{ "name", "sha256" }` for logs or screenshots stored elsewhere. Never inline a secret. |
| `reproduction_steps` | array of string | The exact commands and arguments that reproduce the read-only behavior. |
| `operator_notes` | string | Free-form context; still subject to the redaction rules. |
| `redactions` | array of string | Field paths replaced with `"<REDACTED>"`, so a reviewer knows something was removed deliberately. |

## Redaction rules

Remove, never include:

- seed phrases, secret keys (`S...`), and key material in any encoding;
- signed transactions, signed auth entries, or envelopes — signatures and preimages are not
  evidence a reviewer needs;
- API tokens, bearer headers, or RPC provider keys (strip query strings from `rpc_url`);
- personal data unrelated to the guard account.

Replace a removed value with the literal string `"<REDACTED>"` and add its path to `redactions`.
Public data is fine to keep: contract IDs, `G...` addresses, transaction hashes, ledger numbers,
policy hashes, and event payloads are all public on-chain state. `auth_checked` events and the
other catalogue events carry no key material, so they can be copied unchanged. Prefer
`agent_fingerprint` over the full agent public key: the key is not secret, but the fingerprint is
sufficient for correlation and keeps the bundle compact.

## Collecting a bundle

1. Read the guard state (`--send=no`) and record `policy_hash`, `policy_revision`, and the full
   `status` object.
2. List the incident's transaction hashes in submission order.
3. Pull events for the incident's ledger range (`getEvents` over RPC, or `stellar contract
   events` where the CLI version supports it) and keep only the entries whose `tx_hash` is on the
   list.
4. Record the toolchain versions — the contract's behavior is pinned to them, and a review of a
   different compiler or CLI build is not the same evidence.
5. Redact, then validate the result (a bundle must be one JSON object):

```bash
jq -e '.bundle_version == 1 and (.tx_hashes | length > 0)' bundle.json >/dev/null \
  && echo "bundle shape OK"
```

Checked-in sample: [`examples/incident-evidence-bundle.json`](examples/incident-evidence-bundle.json)
— synthetic values only, and deliberately shaped like a real bundle so a responder can copy it.

## See also

- [Rollback and policy-recovery runbook](rollback-and-recovery.md) — the recovery record this
  bundle formalizes.
- [Deployment record](deployment-runbook.md#deployment-record) — the steady-state baseline a
  bundle's `policy_hash` and `wasm_sha256` are compared against.
- [Testnet verification](../verification.md) — the published evidence set, in the same shape.
- [SPEC §9.2](../../SPEC.md#92-event-catalogue) — the normative event catalogue.
