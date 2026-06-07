# ADR 013: DNS-01 challenge for domain-ownership verification

## Status
Accepted

## Context
Without proof that a registrant controls a domain, the DPKI is Trust-On-First-Use:
whoever submits `RegisterTx` for `example.com` first wins, even if they do not own
it. Verifying control is the project's central research question. Options:

| Option | How | Pros | Cons |
|---|---|---|---|
| DNS-01 | Owner publishes a TXT record at `_dpki-challenge.<domain>` | Industry standard (ACME), supports wildcards, independent of HTTP/HTTPS | Trusts DNS; not everyone controls DNS |
| HTTP-01 | Owner serves a file at `/.well-known/...` | Simple for anyone with a web server | No wildcards; HTTPS chicken-and-egg with DPKI itself |
| X.509 inheritance | Owner signs the challenge with an existing CA-issued cert | Reuses existing PKI | Requires a classical CA — defeats the point of DPKI |

## Decision
Use a **DNS-01-style challenge**, modeled on ACME / Let's Encrypt. The owner
publishes a deterministic value (ADR 015) in a TXT record at
`_dpki-challenge.<domain>`; a validator confirms it with a DNS lookup
(`internal/verifier.DNSVerifier`). The verifier is an interface so a
`MockVerifier` can stand in for tests and DNS-less runs.

## Consequences
- **Positive:** recognized, citable mechanism ("as in Let's Encrypt"); supports
  wildcard domains; independent of the certificate it is bootstrapping, avoiding
  an HTTPS chicken-and-egg.
- **Positive:** a single, well-defined external dependency (DNS) behind a small
  interface; swapping or adding HTTP-01 later is a new implementation, not a
  rewrite.
- **Negative:** security rests on the integrity of DNS resolution; a DNS-spoofing
  adversary can present a false TXT value. The impact is bounded — the attacker
  still lacks the private key and cannot sign a usable transaction — but it is a
  real limitation, discussed in the security analysis. DNSSEC is noted as future
  work.
- **Negative:** domains whose owners cannot edit DNS cannot register; this is the
  same constraint ACME DNS-01 has.
