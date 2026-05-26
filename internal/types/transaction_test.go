package types

import (
	"errors"
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"google.golang.org/protobuf/proto"
)

// validRegisterTx returns a well-formed register transaction for use in tests.
func validRegisterTx(t *testing.T) (*Transaction, []byte, []byte) {
	t.Helper()

	priv, pub, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cert := &Certificate{
		Domain:    "example.com",
		PublicKey: pub,
		Algorithm: Algorithm_ALGORITHM_ED25519,
		ValidFrom: MinValidTimestamp,
	}

	tx := &Transaction{
		Body:    &Transaction_Register{Register: &RegisterTx{Certificate: cert}},
		ChainId: "testchain",
	}

	return tx, priv, pub
}

func TestTransaction_SignBytes_NilTx(t *testing.T) {
	var tx *Transaction
	_, err := tx.SignBytes()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNilTransaction) {
		t.Fatalf("expected ErrNilTransaction, got: %v", err)
	}
}

func TestTransaction_SignBytes_ExcludesSignature(t *testing.T) {
	tx, _, _ := validRegisterTx(t)

	bytesWithout, err := tx.SignBytes()
	if err != nil {
		t.Fatalf("SignBytes (no sig): %v", err)
	}

	tx.Signature = make([]byte, crypto.Ed25519SignatureSize)
	bytesWith, err := tx.SignBytes()
	if err != nil {
		t.Fatalf("SignBytes (with sig): %v", err)
	}

	if string(bytesWithout) != string(bytesWith) {
		t.Fatal("SignBytes differs when Signature is set vs. not set")
	}
}

func TestTransaction_SignBytes_Deterministic(t *testing.T) {
	tx, _, _ := validRegisterTx(t)

	b1, _ := tx.SignBytes()
	b2, _ := tx.SignBytes()

	if string(b1) != string(b2) {
		t.Fatal("SignBytes is not deterministic")
	}
}

func TestTransaction_Hash_NilTx(t *testing.T) {
	var tx *Transaction
	_, err := tx.Hash()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNilTransaction) {
		t.Fatalf("expected ErrNilTransaction, got: %v", err)
	}
}

func TestTransaction_Hash_Length(t *testing.T) {
	tx, _, _ := validRegisterTx(t)

	h, err := tx.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if len(h) != 32 {
		t.Fatalf("Hash length: got %d, want 32", len(h))
	}
}

func TestTransaction_Hash_Deterministic(t *testing.T) {
	tx, _, _ := validRegisterTx(t)

	h1, _ := tx.Hash()
	h2, _ := tx.Hash()

	if string(h1) != string(h2) {
		t.Fatal("Hash is not deterministic")
	}
}

func TestTransaction_Sign_NilTx(t *testing.T) {
	var tx *Transaction
	priv, _, _ := crypto.GenerateEd25519KeyPair()

	err := tx.Sign(priv)
	if err == nil {
		t.Fatal("expected error for nil tx, got nil")
	}
}

func TestTransaction_Sign_SetsSignature(t *testing.T) {
	tx, priv, _ := validRegisterTx(t)

	if err := tx.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if len(tx.Signature) != crypto.Ed25519SignatureSize {
		t.Fatalf("Signature size: got %d, want %d", len(tx.Signature), crypto.Ed25519SignatureSize)
	}
}

func TestTransaction_Sign_InvalidPrivKey(t *testing.T) {
	tx, _, _ := validRegisterTx(t)

	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte{1, 2, 3}},
		{"public key size", make([]byte, crypto.Ed25519PublicKeySize)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tx.Sign(tt.key); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestTransaction_Verify_Valid(t *testing.T) {
	tx, priv, pub := validRegisterTx(t)

	if err := tx.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !tx.Verify(pub) {
		t.Fatal("Verify returned false for a valid signature")
	}
}

func TestTransaction_Verify_NilTx(t *testing.T) {
	var tx *Transaction
	_, pub, _ := crypto.GenerateEd25519KeyPair()

	if tx.Verify(pub) {
		t.Fatal("Verify returned true for nil tx")
	}
}

func TestTransaction_Verify_Unsigned(t *testing.T) {
	tx, _, pub := validRegisterTx(t)

	if tx.Verify(pub) {
		t.Fatal("Verify returned true for unsigned tx")
	}
}

func TestTransaction_Verify_WrongKey(t *testing.T) {
	tx, priv, _ := validRegisterTx(t)

	if err := tx.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, wrongPub, _ := crypto.GenerateEd25519KeyPair()
	if tx.Verify(wrongPub) {
		t.Fatal("Verify returned true with a non-matching public key")
	}
}

func TestTransaction_Verify_ModifiedBody(t *testing.T) {
	tx, priv, pub := validRegisterTx(t)

	if err := tx.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tx.ChainId = "different-chain"
	if tx.Verify(pub) {
		t.Fatal("Verify returned true after modifying the transaction body")
	}
}

func TestTransaction_Verify_TamperedSignature(t *testing.T) {
	tx, priv, pub := validRegisterTx(t)

	if err := tx.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tx.Signature[0] ^= 0xFF
	if tx.Verify(pub) {
		t.Fatal("Verify returned true for a tampered signature")
	}
}

func TestTransaction_BodyType(t *testing.T) {
	tests := []struct {
		name string
		tx   *Transaction
		want string
	}{
		{"nil tx", nil, ""},
		{"empty body", &Transaction{}, ""},
		{
			"register",
			&Transaction{Body: &Transaction_Register{Register: &RegisterTx{}}},
			"register",
		},
		{
			"revoke",
			&Transaction{Body: &Transaction_Revoke{Revoke: &RevokeTx{}}},
			"revoke",
		},
		{
			"rotate",
			&Transaction{Body: &Transaction_Rotate{Rotate: &RotateTx{}}},
			"rotate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tx.BodyType()
			if got != tt.want {
				t.Fatalf("BodyType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTransaction_GetDomainFromBody(t *testing.T) {
	tests := []struct {
		name string
		tx   *Transaction
		want string
	}{
		{"nil tx", nil, ""},
		{"empty body", &Transaction{}, ""},
		{
			"register",
			&Transaction{
				Body: &Transaction_Register{
					Register: &RegisterTx{
						Certificate: &Certificate{Domain: "example.com"},
					},
				},
			},
			"example.com",
		},
		{
			"register with nil cert",
			&Transaction{
				Body: &Transaction_Register{
					Register: &RegisterTx{Certificate: nil},
				},
			},
			"", // GetCertificate() na nil-Register → nil → GetDomain() → ""
		},
		{
			"revoke",
			&Transaction{
				Body: &Transaction_Revoke{
					Revoke: &RevokeTx{Domain: "test.com"},
				},
			},
			"test.com",
		},
		{
			"rotate",
			&Transaction{
				Body: &Transaction_Rotate{
					Rotate: &RotateTx{Domain: "rotate.com"},
				},
			},
			"rotate.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tx.GetDomainFromBody()
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzTransactionDeserialize(f *testing.F) {
	tx := &Transaction{
		Body:    &Transaction_Revoke{Revoke: &RevokeTx{Domain: "example.com", Nonce: 1}},
		ChainId: "testchain",
	}
	seed, _ := proto.Marshal(tx)

	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed := &Transaction{}
		if err := proto.Unmarshal(data, parsed); err != nil {
			return
		}
		_ = parsed.Validate()
		_, _ = parsed.SignBytes()
		_, _ = parsed.Hash()
		_ = parsed.BodyType()
		_ = parsed.GetDomainFromBody()
	})
}
