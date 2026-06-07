// Package verifier proves that the submitter of a domain registration actually
// controls the domain, turning the DPKI from Trust-On-First-Use into an
// authenticated registry (the project's core design contribution).
//
// The mechanism is a DNS-01-style challenge modeled on ACME / Let's Encrypt: the
// domain owner publishes a deterministic, key-bound value (ChallengeValue) in a
// TXT record at ChallengeName(domain), and a validator confirms it with a DNS
// lookup. Binding the challenge to the registrant's public key defeats
// front-running; binding it to the chain ID prevents cross-chain reuse.
//
// A DNS lookup is non-deterministic external I/O, so verification is a
// pre-consensus admission gate only (CheckTx, ProcessProposal) and never part of
// the deterministic state machine in FinalizeBlock.
//
// Types:
//
//   - Verifier      — the interface the application depends on.
//   - DNSVerifier   — the DNS-01 implementation over a TXTResolver.
//   - MockVerifier  — a deterministic stand-in for tests and DNS-less runs.
package verifier
