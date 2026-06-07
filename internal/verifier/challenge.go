package verifier

import (
	"encoding/hex"
	"slices"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
)

// ChallengePrefix is the DNS label under which the challenge TXT record lives,
// mirroring ACME's "_acme-challenge". The record for example.com is published at
// _dpki-challenge.example.com.
const ChallengePrefix = "_dpki-challenge."

// ChallengeName returns the fully qualified name of the TXT record a domain
// owner must publish to prove control of domain.
func ChallengeName(domain string) string {
	return ChallengePrefix + domain
}

// ChallengeValue computes the deterministic challenge string a domain owner must
// publish in the challenge TXT record. Both the client (when instructing the
// user) and every validator (when checking) compute it identically, so it is
// derived purely from public, transaction-bound inputs:
//
//	SHA-256( domain || 0x00 || pubKey || 0x00 || chainID )
//
// The NUL separators give domain separation so that, e.g., ("ab", "c") and
// ("a", "bc") cannot collide. Binding the value to:
//
//   - the public key prevents front-running: an attacker copying a pending
//     registration uses a different key, so their expected value differs from
//     the record the real owner published;
//   - the chain ID stops a challenge published for one chain being reused on
//     another.
//
// The value is returned as lower-case hex (64 characters).
func ChallengeValue(domain string, pubKey []byte, chainID string) string {
	preimage := slices.Concat(
		[]byte(domain), []byte{0x00},
		pubKey, []byte{0x00},
		[]byte(chainID),
	)
	return hex.EncodeToString(crypto.Hash(preimage))
}
