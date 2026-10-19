# Support

Three channels point at this project and they are not interchangeable. This page
says which one to use for what, and what response to expect. For the security
disclosure process itself — scope, report template, advisory policy — see
[SECURITY.md](SECURITY.md); this page only routes you to it.

## Where to go

| You have | Use | Do not use |
| --- | --- | --- |
| A bug, a confusing rejection, a feature request | [GitHub issues](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues) | Telegram or Discord — the discussion is unsearchable and the fix loses its thread |
| A question about how to use the contract, policy tuning, deployment help | [Telegram group](https://t.me/+EzSusj-2vVhhNmI0) or [Discord server](https://discord.gg/Z766vsgjg) | The issue tracker, unless the answer turns out to be a bug (then file it) |
| A vulnerability, or anything that could move funds if abused | **Private** route only: [GitHub private vulnerability reporting](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/security/advisories/new), or the email fallback in [SECURITY.md](SECURITY.md#reporting-a-vulnerability) | Telegram, Discord, public issues, PRs, or any open chat thread |
| A *deployed instance* behaving wrong (its policy, not this code) | That instance's operator | This tracker — see [SECURITY.md → Scope](SECURITY.md#scope) |

Stellar Agent Guard spans three repositories, so before you file, use the
[decision table in the README](README.md#which-repository--decision-table-for-cross-repo-questions)
to pick the right one. Contract-vs-SDK encoding disagreements go in both, linked
to each other.

## Security disclosures: the private route, and why

The **only** disclosure route whose ownership is verifiable from outside is this
repository's GitHub private vulnerability reporting. It is private to you and the
maintainers, it creates a trackable `GHSA` advisory, and it keeps report, fix and
disclosure in one auditable place.

The [Telegram group](https://t.me/+EzSusj-2vVhhNmI0) and the
[Discord server](https://discord.gg/Z766vsgjg) are community channels reached
through invite links. An invite link does not identify who controls the channel,
and we could not verify that either one is maintainer-owned at the time of
writing. That is not an accusation — it is simply not something you can check
before you paste a vulnerability into it, and a disclosure that lands in a public
group is already disclosed. **Use the public channels for non-sensitive
questions only.** If the only way you can reach a maintainer is a chat channel,
send a one-line request for the private route (the advisory link, or a PGP key
for the email fallback) and put the report itself in the private channel.

The report template — affected version or commit, description, impact including
whether funds are at risk, reproduction, suggested fix — is in
[SECURITY.md](SECURITY.md#what-to-include-in-a-report).

## Response expectations

One commitment is made on this page and it is the security one, already stated in
[SECURITY.md](SECURITY.md#what-youll-get-back): 48 hours to acknowledge, 7 days to
assess. The rest of this table describes **how this repository actually works** — a
volunteer-maintained project with no on-call rotation, no support contract, and one
maintainer — so that you can decide how much to depend on a given channel before you
depend on it. A quiet channel is not evidence that your report was ignored.

| Channel | What it is for | What to expect |
| --- | --- | --- |
| Private vulnerability report / security email | Confirmed or suspected vulnerabilities | Acknowledged within **48 hours**; assessment and remediation plan (or a status update) within **7 days**. This is a commitment, and the only one on this page. See [SECURITY.md](SECURITY.md#what-youll-get-back) |
| GitHub issues | Bugs, feature requests, spec questions | No turnaround is promised. Issues are labeled by `complexity:` and worked from the backlog, so an unanswered issue after a week is normal, not a rejection. A `closed as not planned` carries a reason; it is a decision, not a slight |
| Telegram / Discord | Usage questions, policy tuning, general discussion | Best-effort and asymmetric: answers often arrive same-day during active hours, sometimes never, and weekends are quiet. Chat answers are not authoritative — [SPEC.md](SPEC.md) and the tests are, so anything that matters gets written down in an issue |
| Deployed instance problems | Operator-side configuration | Out of scope here; whoever deployed that instance owns its response time |

If a security report gets no acknowledgement after 48 hours, resend it through the
other private route (advisory → email, or email → advisory) rather than following
up in a public channel.

## Before you ask: bug, or a gate doing its job?

This contract gates fund movement for autonomous agents, so most "support" traffic
is really operator configuration: a blocked transfer usually means a gate did its
job. Before asking, read the [reason glossary](docs/reason-glossary.md) and
[SPEC §4](SPEC.md#4-policy-semantics--decision-table) — the block `reason` symbol
names the gate and the rule that fired, and `check` returns the same verdict as a
pre-flight read without submitting anything (SPEC §7.2). Include the `reason`
symbol, the policy you installed, and the ledger/time conditions when you do ask.
