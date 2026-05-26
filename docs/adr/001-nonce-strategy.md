# ADR 001: Per-domain nonce strategy

## Status
Accepted

## Context
Revoke and Rotate transactions must be protected against replay attacks: an
attacker who captures a valid signed transaction must not be able to resubmit
it later (e.g. after the owner has rotated back to an old key, or re-registered
a domain).

Several anti-replay strategies exist:
- **Global sequence number per sender** — simple, but ties replay protection
  to a single public key identity rather than to a domain.
- **Transaction hash in state** — prevents exact replays, but requires storing
  every seen hash indefinitely.
- **Per-domain nonce** — a monotonically increasing counter kept in state for
  each domain; a transaction is only valid if its nonce equals current + 1.

## Decision
Use a per-domain nonce stored in the application state. The nonce is included
in `RevokeTx` and `RotateTx` and must be greater than zero. It is absent from
`RegisterTx` because the domain does not yet exist in state (see ADR 004).

## Consequences
- **Positive:** the nonce space is independent between domains; compromise of
  one domain's key does not affect nonce ordering for others.
- **Positive:** nonce validation is stateless from the transaction's point of
  view — the application simply compares tx.Nonce against the stored value.
- **Negative:** the application layer must load current nonce from state on
  every Revoke/Rotate, adding one state read per transaction.
- **Negative:** if a domain is deleted and re-registered the nonce resets to
  zero, which must be handled carefully to avoid replaying old revocations.
