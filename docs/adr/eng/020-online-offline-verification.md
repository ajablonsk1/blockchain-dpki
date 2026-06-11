# ADR 020: Online and offline verification paths

## Status
Accepted

## Context
A relying party asks: "is this the current, non-revoked key for domain X?"
The DPKI's core claim (ADR 007, 010) is that the answer is *self-verifying* —
a Merkle proof against a committed app hash — so the client should never have
to take a node's word for it. One subtlety: ABCI commits the app hash late.
The state after block H is committed in the header of block **H+1**, so a
proof for query height H verifies against `header(H+1).AppHash`.

## Decision
Three read paths, all ending in `state.VerifyDomainProof`:

1. **`lookup`** (single node) — fetches state + proof, resolves the root from
   the next block header (polling briefly at the chain tip), verifies locally
   and only then prints. There is deliberately **no unverified read** in the
   CLI: even plain lookup authenticates what it shows.
2. **`verify --nodes a,b,c`** (multi-node) — runs the lookup verification
   against every node, then cross-checks: all proven states must be equal and
   nodes at the same height must report the same app hash. A single
   compromised node is caught unless it can also fork the headers of the
   others; the trust anchor is the validator set, not any one RPC endpoint.
3. **`verify-offline`** — consumes a proof bundle saved by
   `lookup --save-proof` (chain id, domain, height, proof bytes) plus a root
   passed explicitly via `--root`. The bundle also records the app hash it was
   issued against, but that copy is **informational only**: trusting it would
   collapse the proof into "the file says so". Obtaining the root out of band
   is the point of offline verification. `--cert` optionally cross-checks an
   out-of-band certificate against the proven state.

## Consequences
- **Positive:** revocation checking needs no CRL/OCSP-style infrastructure; a
  stale answer cannot be replayed against a newer root.
- **Positive:** non-inclusion is first-class — "domain not registered" is a
  verifiable statement, not an error.
- **Negative:** online paths trust the queried node for *headers*; full light
  client verification (validator signatures over headers) is future work for
  the multi-node phase. The multi-node cross-check narrows the gap until then.
- **Negative:** at the chain tip the client may wait ~1 block for the header
  that commits the queried state.
