# Storage rent and TTL cost model

This note is for operators and contributors maintaining a long-lived guard account. The guard keeps `Policy`, `Window`, `LastHeartbeat`, and `AdminFrozen` in persistent storage. Writes extend each key to the host's maximum TTL (currently about 180 days at the usual five-second ledger close time); successful reads refresh a key to maximum TTL if less than half remains. The `Window` value grows with its spend entries, up to the code-level `MAX_WINDOW_ENTRIES` limit of 8,192.

## Who pays

Soroban rent is part of the transaction resource fee and is paid by that transaction's fee-paying account in XLM. In the ordinary self-paid setup, budget XLM in the guard account for operations it submits. If a relayer or fee-bump sponsor pays, that payer funds the rent instead. Contract storage itself does not have an independently debited XLM balance. Rent is charged when an entry is created, grows, or gets a longer TTL; deleting or shrinking it does not refund prior rent.

## Approximate scale

Rent is proportional to the serialized persistent-entry size and the number of ledgers added to its TTL. It is network-configurable, so these are order-of-magnitude planning figures, not a quote. For a reproducible baseline, use the Protocol 23+ rent equation in [CAP-66](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md):

```text
rent (stroops) ≈ bytes × ledgers × rent_fee_per_1kb / (1024 × persistentRentRateDenominator)
```

Using the mainnet settings queried on 2026-09-29 (3,110,400 ledgers maximum TTL; persistent rent denominator 1,215; 10,000 stroops per KiB as the high-state reference rate) gives about **2.56 XLM per KiB per maximum-TTL extension**. This is an upper-baseline estimate: the actual rent rate is dynamic with live Soroban state size. Reproduce the inputs with `stellar network settings --network mainnet`, apply the [CAP-66](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md) rate formula, or simulate the exact transaction before budgeting.

| Window size | Approximate storage basis | Approximate rent for one maximum-TTL extension |
|---|---:|---:|
| 1 spend entry (smallest nonempty window) | ~128 bytes including key/entry overhead | ~0.32 XLM |
| 8,192 spend entries (configured ceiling, theoretical) | ~416 KiB, using ~52 serialized bytes per entry | ~1,065 XLM |
| Largest entry Soroban can serialize | 64 KiB | ~163.84 XLM |

The 8,192-entry figure is a cost-model extrapolation, not a claim that one Soroban value can hold that many entries. Contract-data ledger entries have a 64 KiB serialized size limit, so an actual `Window` reaches that limit well before the configured entry ceiling; the exact usable count depends on XDR overhead. Keep the operational window bounded well below both limits. The max-TTL estimate is for extending the full remaining lifetime from near expiry; if a write only adds `L` ledgers, scale the rent component by `L / 3,110,400`. Each extension also has a TTL-entry write fee, and live rates may differ. For transaction-specific fees, simulate with the intended footprint and payer.

The entry-count cap is still useful as a defensive bound: it prevents unbounded growth in contract logic and makes the rent exposure finite. Same-second spends coalesce, and when the cap is exceeded, the oldest two entries merge forward (conservative accounting); see [SPEC §3.1](../SPEC.md#31-the-window-is-genuinely-rolling--not-a-fixed-bucket). Submitting a successful read call can incur rent when it refreshes TTL; RPC simulations (`send=no`) do not persist the TTL update.

## Underfunded extension and expiry

If the transaction's fee payer cannot cover the resource fee, including rent for a TTL extension, the transaction fails and the extension does not take effect. The stored key keeps its prior TTL. If no later successful write or TTL extension occurs before that TTL reaches zero, the persistent entry is archived. A later transaction must include it in a restore footprint before contract code can read it; current RPC simulation normally adds archived entries automatically. If restoration cannot be funded, or an archived entry is omitted from the footprint, that transaction fails before the guard can authorize a spend. A successful read refreshes the restored entry's TTL as described in [SPEC §9.5](../SPEC.md#95-persistent-storage-ttl-liveness). This is the behavior investigated by [issue #43: prove Window/Policy cannot silently expire mid-window](https://github.com/aigbagbobila/stellar-agent-guard-contracts/issues/43).

Operators should keep the configured fee payer funded, monitor successful guard writes, and restore archived persistent state before relying on an account whose keys have expired. Read Stellar's [state archival guide](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival) for the network restoration flow.
