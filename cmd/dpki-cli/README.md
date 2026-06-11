# dpki-cli

CLI client for the DPKI blockchain. It manages Ed25519 keypairs, registers,
rotates and revokes domain certificates, and looks up certificates together
with Merkle proofs that verify against the chain's committed app hash — also
fully offline.

The client contains no business logic: every validation decision is made by
the node. The only cryptographic work done locally is transaction signing and
Merkle-proof verification (ADR 017, 020).

## Build

```bash
make build          # produces ./bin/dpki-cli (and ./bin/dpkid)
```

## Quickstart

```bash
# 0. Have a node running (single-node dev chain):
./bin/dpkid init --chain-id dpki-testnet-1
./bin/dpkid start                      # add --no-verify to skip DNS checks locally

# 1. Generate a keypair
dpki-cli keys generate --output ~/.dpki/keys/mykey.priv

# 2. Print the DNS-01 challenge record and publish it in your zone
dpki-cli challenge --domain example.com --keyfile ~/.dpki/keys/mykey.priv

# 3. Confirm the record propagated
dpki-cli challenge-check --domain example.com --keyfile ~/.dpki/keys/mykey.priv

# 4. Register the domain (waits for ENTER unless --skip-challenge)
dpki-cli register --domain example.com --keyfile ~/.dpki/keys/mykey.priv

# 5. Look it up — the proof is verified locally before anything is printed
dpki-cli lookup --domain example.com --save-proof proof.json --save-cert cert.json

# 6. Verify against several nodes (no single node needs to be trusted)
dpki-cli verify --domain example.com --nodes node1:26657,node2:26657

# 7. Verify the saved proof later, without any network access
dpki-cli verify-offline --proof proof.json --root <trusted_app_hash_hex> --cert cert.json

# 8. Rotate to a new key (the OLD key signs)
dpki-cli rotate --domain example.com --keyfile mykey.priv --new-keyfile newkey.priv

# 9. Revoke
dpki-cli revoke --domain example.com --keyfile newkey.priv --reason "key compromised"
```

## Commands

| Command           | Purpose                                                          |
|-------------------|------------------------------------------------------------------|
| `keys generate`   | Create an Ed25519 keypair (file mode 0600, never overwrites)     |
| `keys show`       | Print public key, fingerprint, algorithm — never the private key |
| `challenge`       | Print the DNS-01 TXT record proving domain ownership             |
| `challenge-check` | Query DNS and report whether the record matches                  |
| `register`        | Build, sign and broadcast a RegisterTx                           |
| `rotate`          | Replace the domain key; signed with the current key              |
| `revoke`          | Revoke the certificate; nonce fetched from current state         |
| `lookup`          | Fetch state + Merkle proof, verify locally, print                |
| `verify`          | Lookup on N nodes and cross-check their answers                  |
| `verify-offline`  | Verify a saved proof bundle against an explicit trusted root     |
| `status`          | Chain id, latest height and app hash of the node                 |
| `completion`      | Shell autocompletion (bash/zsh/fish/powershell)                  |

Every command supports `--help`.

## Global flags and configuration

| Flag          | Default                  | Config key        |
|---------------|--------------------------|-------------------|
| `--node`      | `http://localhost:26657` | `node`            |
| `--chain-id`  | asked from the node      | `chain_id`        |
| `--config`    | `~/.dpki/config.yaml`    | —                 |
| `-v --verbose`| off                      | —                 |
| `--keyfile`   | (per command)            | `default_keyfile` |

Precedence: explicit flag > config file > default. Example config:

```yaml
# ~/.dpki/config.yaml
node: http://localhost:26657
chain_id: dpki-testnet-1
default_keyfile: ~/.dpki/keys/mykey.priv
```

The chain id used in transactions is always cross-checked against the node's
actual chain id; a mismatch aborts before signing.

`-v` prints the canonical sign bytes, the signature, the node's raw
CheckTx/ExecTx verdicts and proof details to stderr — useful when debugging.

## Proof bundles

`lookup --save-proof FILE` writes a JSON bundle (chain id, domain, height,
app hash, proof bytes). `verify-offline` re-verifies it with **no network**:

```bash
dpki-cli verify-offline --proof proof.json --root <app_hash_hex>
```

The root must come from a source you trust (several nodes, a block explorer);
the app hash recorded inside the bundle is informational only — see ADR 020.

## Trust model in one paragraph

`lookup` proves its answer against the app hash committed in the next block
header. `verify` repeats that against many nodes and requires their answers to
agree, so no single RPC endpoint has to be trusted. `verify-offline` removes
the network entirely: given a proof bundle and a trusted root, the answer —
including "this domain is provably not registered" and "this certificate is
revoked" — verifies on pure math. This replaces CRL/OCSP-style availability
requirements of classical PKI.

## Tests

```bash
go test ./cmd/dpki-cli/...   # unit tests against an in-process mock node
./scripts/test-e2e.sh        # full lifecycle against a real dpkid node
```
