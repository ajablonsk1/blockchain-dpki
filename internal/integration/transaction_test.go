package integration_test

import (
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/testhelpers"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
	"google.golang.org/protobuf/proto"
)

// TestRegisterTx_HappyPath simulates the full lifecycle of a RegisterTx:
// key generation → certificate creation → signing → serialization →
// deserialization → validation → signature verification.
func TestRegisterTx_HappyPath(t *testing.T) {
	// 1. Generate key pair
	priv, pub := testhelpers.MustGenerateKeyPair(t)

	// 2. Create certificate
	cert := testhelpers.MustNewCertificate(t, "example.com", pub)

	// 3. Build and sign RegisterTx
	tx, err := types.NewRegisterTx(cert, "testchain")
	if err != nil {
		t.Fatalf("NewRegisterTx: %v", err)
	}
	if err := tx.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// 4. Serialize (simulate network transit)
	wire, err := proto.Marshal(tx)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	// 5. Deserialize
	received := &types.Transaction{}
	if err := proto.Unmarshal(wire, received); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}

	// 6. Validate structure
	if err := received.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// 7. Extract public key from the embedded certificate and verify signature
	receivedPub := received.GetRegister().GetCertificate().GetPublicKey()
	if !received.Verify(receivedPub) {
		t.Fatal("Verify returned false for a correctly signed transaction")
	}
}

// TestRegisterTx_TamperedDomain signs a transaction then modifies the
// certificate domain inside the body; Verify must return false.
func TestRegisterTx_TamperedDomain(t *testing.T) {
	tx, _ := testhelpers.MustNewSignedRegisterTx(t, "example.com")

	pub := tx.GetRegister().GetCertificate().GetPublicKey()
	tx.GetRegister().GetCertificate().Domain = "evil.com"

	if tx.Verify(pub) {
		t.Fatal("Verify returned true after tampering with Certificate.Domain")
	}
}

// TestRegisterTx_TamperedSignature signs a transaction then flips a bit in
// the signature; Verify must return false.
func TestRegisterTx_TamperedSignature(t *testing.T) {
	tx, _ := testhelpers.MustNewSignedRegisterTx(t, "example.com")

	pub := tx.GetRegister().GetCertificate().GetPublicKey()
	tx.Signature[0] ^= 0xFF

	if tx.Verify(pub) {
		t.Fatal("Verify returned true after tampering with Signature")
	}
}

// TestRegisterTx_TamperedChainID signs a transaction then changes ChainId;
// Verify must return false.
func TestRegisterTx_TamperedChainID(t *testing.T) {
	tx, _ := testhelpers.MustNewSignedRegisterTx(t, "example.com")

	pub := tx.GetRegister().GetCertificate().GetPublicKey()
	tx.ChainId = "attacker-chain"

	if tx.Verify(pub) {
		t.Fatal("Verify returned true after tampering with ChainId")
	}
}

// TestRotateTx_WrongSigningKey is a skeleton for a future business-logic
// check: a RotateTx must be signed by the *current* owner's key, not the new
// one. This test documents the expected behaviour; enforcement belongs in the
// ABCI application layer (it requires access to current state), not here.
func TestRotateTx_WrongSigningKey(t *testing.T) {
	_, currentPub := testhelpers.MustGenerateKeyPair(t)
	newPriv, newPub := testhelpers.MustGenerateKeyPair(t)

	// Build RotateTx and sign it with the *new* key — wrong owner.
	tx := testhelpers.MustNewSignedRotateTx(t, "example.com", 1, newPriv, newPub)

	// At the crypto layer the signature is structurally valid (correct key
	// size, correct signature size), so Verify with the new key passes.
	if !tx.Verify(newPub) {
		t.Fatal("sanity: Verify with the signing key should pass")
	}

	// But Verify with the *current* owner's key must fail — the tx was not
	// signed by the legitimate owner.
	if tx.Verify(currentPub) {
		t.Fatal("Verify returned true with the wrong (current owner's) key")
	}

	// TODO: add an ABCI-layer test that rejects a RotateTx whose signer does
	// not match the public key stored in state for that domain.
	_ = crypto.Ed25519PublicKeySize // silence unused-import lint until TODO is done
}
