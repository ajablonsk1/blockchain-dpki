# ADR 016: Client-side grace period for DNS propagation

## Status
Accepted

## Context
After the owner publishes the challenge TXT record, it takes time to propagate
through DNS caches (bounded by the record's TTL). If a validator looks it up too
soon it may see a stale negative answer and reject an otherwise-valid
registration. Three mitigations exist:

- **Grace period (client-side):** the owner waits before submitting the
  `RegisterTx`, and sets a low TTL so propagation is fast.
- **Retries with backoff (validator-side):** the verifier retries a few times
  before giving up.
- **Authoritative query (validator-side):** the verifier resolves the domain's
  authoritative nameservers and queries them directly, bypassing caches.

## Decision
For the MVP, rely on a **client-side grace period**: the `dpki-cli challenge`
command instructs the owner to publish the record with a low TTL (e.g. 60s) and
to confirm propagation with `dpki-cli challenge-check` before submitting the
transaction. The validator performs a single, ordinary DNS lookup using Go's
`PreferGo` resolver. Retries/backoff and authoritative queries are documented as
future work.

## Consequences
- **Positive:** the validator stays simple — one lookup, no retry state machine,
  no nameserver discovery — which keeps the verification path easy to reason
  about and test.
- **Positive:** `challenge-check` gives the user a concrete "is it ready yet?"
  signal, moving the propagation concern to where the human is waiting anyway.
- **Negative:** a user who submits too early, or whose resolver path is slow to
  propagate, can have a valid registration rejected and must retry. With a low
  TTL this window is small.
- **Negative:** a single lookup is more sensitive to transient DNS failures than
  a retrying one; combined with ADR 014 (DNS in `ProcessProposal`) this is a
  liveness consideration for a future multi-node deployment, not a correctness
  one.
