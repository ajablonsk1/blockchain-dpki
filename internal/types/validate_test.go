package types

import (
	"errors"
	"strings"
	"testing"
)

// --- helpers ---

func validKey() []byte {
	return make([]byte, Ed25519KeySize)
}

func validSig() []byte {
	return make([]byte, Ed25519SigSize)
}

func validCert() *Certificate {
	return &Certificate{
		Domain:    "example.com",
		PublicKey: validKey(),
		Algorithm: Algorithm_ALGORITHM_ED25519,
		ValidFrom: MinValidTimestamp + 1,
	}
}

// --- validatePublicKey ---

func TestValidatePublicKey(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		algo    Algorithm
		wantErr error
	}{
		// --- happy paths ---
		{
			name:    "valid ed25519 key",
			key:     make([]byte, Ed25519KeySize),
			algo:    Algorithm_ALGORITHM_ED25519,
			wantErr: nil,
		},

		// --- errors: algorithm ---
		{
			name:    "unspecified algorithm",
			key:     make([]byte, Ed25519KeySize),
			algo:    Algorithm_ALGORITHM_UNSPECIFIED,
			wantErr: ErrUnknownAlgorithm,
		},
		{
			name:    "ecdsa p256 not supported",
			key:     make([]byte, Ed25519KeySize),
			algo:    Algorithm_ALGORITHM_ECDSA_P256,
			wantErr: ErrAlgorithmNotSupported,
		},
		{
			name:    "unknown algorithm value",
			key:     make([]byte, Ed25519KeySize),
			algo:    Algorithm(9999),
			wantErr: ErrUnknownAlgorithm,
		},

		// --- errors: ed25519 key size ---
		{
			name:    "ed25519 key too short",
			key:     make([]byte, Ed25519KeySize-1),
			algo:    Algorithm_ALGORITHM_ED25519,
			wantErr: ErrInvalidKeySize,
		},
		{
			name:    "ed25519 key too long",
			key:     make([]byte, Ed25519KeySize+1),
			algo:    Algorithm_ALGORITHM_ED25519,
			wantErr: ErrInvalidKeySize,
		},
		{
			name:    "ed25519 key empty",
			key:     []byte{},
			algo:    Algorithm_ALGORITHM_ED25519,
			wantErr: ErrInvalidKeySize,
		},
		{
			name:    "ed25519 key nil",
			key:     nil,
			algo:    Algorithm_ALGORITHM_ED25519,
			wantErr: ErrInvalidKeySize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePublicKey(tt.key, tt.algo)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no err, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

// --- Certificate.Validate ---

func TestCertificate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cert    *Certificate
		wantErr error
	}{
		// --- happy paths ---
		{
			name:    "valid certificate",
			cert:    validCert(),
			wantErr: nil,
		},
		{
			name: "valid at min timestamp",
			cert: &Certificate{
				Domain:    "example.com",
				PublicKey: validKey(),
				Algorithm: Algorithm_ALGORITHM_ED25519,
				ValidFrom: MinValidTimestamp,
			},
			wantErr: nil,
		},

		// --- errors: nil ---
		{
			name:    "nil certificate",
			cert:    nil,
			wantErr: ErrNilCertificate,
		},

		// --- errors: domain (delegated) ---
		{
			name: "empty domain",
			cert: &Certificate{
				Domain:    "",
				PublicKey: validKey(),
				Algorithm: Algorithm_ALGORITHM_ED25519,
				ValidFrom: MinValidTimestamp,
			},
			wantErr: ErrEmptyDomain,
		},
		{
			name: "invalid domain format",
			cert: &Certificate{
				Domain:    "no-dots-here",
				PublicKey: validKey(),
				Algorithm: Algorithm_ALGORITHM_ED25519,
				ValidFrom: MinValidTimestamp,
			},
			wantErr: ErrInvalidDomainFormat,
		},

		// --- errors: public key (delegated) ---
		{
			name: "invalid key size",
			cert: &Certificate{
				Domain:    "example.com",
				PublicKey: make([]byte, 16),
				Algorithm: Algorithm_ALGORITHM_ED25519,
				ValidFrom: MinValidTimestamp,
			},
			wantErr: ErrInvalidKeySize,
		},
		{
			name: "unspecified algorithm",
			cert: &Certificate{
				Domain:    "example.com",
				PublicKey: validKey(),
				Algorithm: Algorithm_ALGORITHM_UNSPECIFIED,
				ValidFrom: MinValidTimestamp,
			},
			wantErr: ErrUnknownAlgorithm,
		},
		{
			name: "unsupported algorithm",
			cert: &Certificate{
				Domain:    "example.com",
				PublicKey: validKey(),
				Algorithm: Algorithm_ALGORITHM_ECDSA_P256,
				ValidFrom: MinValidTimestamp,
			},
			wantErr: ErrAlgorithmNotSupported,
		},

		// --- errors: timestamp ---
		{
			name: "timestamp zero",
			cert: &Certificate{
				Domain:    "example.com",
				PublicKey: validKey(),
				Algorithm: Algorithm_ALGORITHM_ED25519,
				ValidFrom: 0,
			},
			wantErr: ErrInvalidTimestamp,
		},
		{
			name: "timestamp below min",
			cert: &Certificate{
				Domain:    "example.com",
				PublicKey: validKey(),
				Algorithm: Algorithm_ALGORITHM_ED25519,
				ValidFrom: MinValidTimestamp - 1,
			},
			wantErr: ErrInvalidTimestamp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cert.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no err, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

// --- RegisterTx.Validate ---

func TestRegisterTx_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tx      *RegisterTx
		wantErr error
	}{
		// --- happy paths ---
		{
			name:    "valid register",
			tx:      &RegisterTx{Certificate: validCert()},
			wantErr: nil,
		},

		// --- errors: nil ---
		{
			name:    "nil register tx",
			tx:      nil,
			wantErr: ErrNilRegisterTx,
		},
		{
			name:    "nil certificate",
			tx:      &RegisterTx{Certificate: nil},
			wantErr: ErrNilCertificate,
		},

		// --- errors: cert validation (delegated) ---
		{
			name: "invalid domain in cert",
			tx: &RegisterTx{Certificate: &Certificate{
				Domain:    "",
				PublicKey: validKey(),
				Algorithm: Algorithm_ALGORITHM_ED25519,
				ValidFrom: MinValidTimestamp,
			}},
			wantErr: ErrEmptyDomain,
		},
		{
			name: "invalid key in cert",
			tx: &RegisterTx{Certificate: &Certificate{
				Domain:    "example.com",
				PublicKey: make([]byte, 10),
				Algorithm: Algorithm_ALGORITHM_ED25519,
				ValidFrom: MinValidTimestamp,
			}},
			wantErr: ErrInvalidKeySize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tx.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no err, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

// --- RevokeTx.Validate ---

func TestRevokeTx_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tx      *RevokeTx
		wantErr error
	}{
		// --- happy paths ---
		{
			name: "valid revoke",
			tx: &RevokeTx{
				Domain: "example.com",
				Nonce:  1,
				Reason: "key compromised",
			},
			wantErr: nil,
		},
		{
			name: "valid revoke empty reason",
			tx: &RevokeTx{
				Domain: "example.com",
				Nonce:  1,
				Reason: "",
			},
			wantErr: nil,
		},
		{
			name: "valid revoke reason at max length",
			tx: &RevokeTx{
				Domain: "example.com",
				Nonce:  1,
				Reason: strings.Repeat("a", MaxReasonLength),
			},
			wantErr: nil,
		},

		// --- errors: nil ---
		{
			name:    "nil revoke tx",
			tx:      nil,
			wantErr: ErrNilRevokeTx,
		},

		// --- errors: domain (delegated) ---
		{
			name: "empty domain",
			tx: &RevokeTx{
				Domain: "",
				Nonce:  1,
			},
			wantErr: ErrEmptyDomain,
		},
		{
			name: "invalid domain format",
			tx: &RevokeTx{
				Domain: "no-dots",
				Nonce:  1,
			},
			wantErr: ErrInvalidDomainFormat,
		},

		// --- errors: nonce ---
		{
			name: "nonce zero",
			tx: &RevokeTx{
				Domain: "example.com",
				Nonce:  0,
			},
			wantErr: ErrNonceEqualZero,
		},

		// --- errors: reason ---
		{
			name: "reason too long",
			tx: &RevokeTx{
				Domain: "example.com",
				Nonce:  1,
				Reason: strings.Repeat("a", MaxReasonLength+1),
			},
			wantErr: ErrReasonTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tx.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no err, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

// --- RotateTx.Validate ---

func TestRotateTx_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tx      *RotateTx
		wantErr error
	}{
		// --- happy paths ---
		{
			name: "valid rotate",
			tx: &RotateTx{
				Domain:       "example.com",
				Nonce:        1,
				NewPublicKey: validKey(),
				NewAlgorithm: Algorithm_ALGORITHM_ED25519,
			},
			wantErr: nil,
		},

		// --- errors: nil ---
		{
			name:    "nil rotate tx",
			tx:      nil,
			wantErr: ErrNilRotateTx,
		},

		// --- errors: domain (delegated) ---
		{
			name: "empty domain",
			tx: &RotateTx{
				Domain:       "",
				Nonce:        1,
				NewPublicKey: validKey(),
				NewAlgorithm: Algorithm_ALGORITHM_ED25519,
			},
			wantErr: ErrEmptyDomain,
		},
		{
			name: "invalid domain format",
			tx: &RotateTx{
				Domain:       "no-dots",
				Nonce:        1,
				NewPublicKey: validKey(),
				NewAlgorithm: Algorithm_ALGORITHM_ED25519,
			},
			wantErr: ErrInvalidDomainFormat,
		},

		// --- errors: nonce ---
		{
			name: "nonce zero",
			tx: &RotateTx{
				Domain:       "example.com",
				Nonce:        0,
				NewPublicKey: validKey(),
				NewAlgorithm: Algorithm_ALGORITHM_ED25519,
			},
			wantErr: ErrNonceEqualZero,
		},

		// --- errors: new public key (delegated) ---
		{
			name: "invalid new key size",
			tx: &RotateTx{
				Domain:       "example.com",
				Nonce:        1,
				NewPublicKey: make([]byte, 16),
				NewAlgorithm: Algorithm_ALGORITHM_ED25519,
			},
			wantErr: ErrInvalidKeySize,
		},
		{
			name: "unspecified new algorithm",
			tx: &RotateTx{
				Domain:       "example.com",
				Nonce:        1,
				NewPublicKey: validKey(),
				NewAlgorithm: Algorithm_ALGORITHM_UNSPECIFIED,
			},
			wantErr: ErrUnknownAlgorithm,
		},
		{
			name: "unsupported new algorithm",
			tx: &RotateTx{
				Domain:       "example.com",
				Nonce:        1,
				NewPublicKey: validKey(),
				NewAlgorithm: Algorithm_ALGORITHM_ECDSA_P256,
			},
			wantErr: ErrAlgorithmNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tx.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no err, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

// --- Transaction.Validate ---

func TestTransaction_Validate(t *testing.T) {
	validRegisterBody := &Transaction_Register{Register: &RegisterTx{Certificate: validCert()}}
	validRevokeBody := &Transaction_Revoke{Revoke: &RevokeTx{Domain: "example.com", Nonce: 1}}
	validRotateBody := &Transaction_Rotate{Rotate: &RotateTx{
		Domain:       "example.com",
		Nonce:        1,
		NewPublicKey: validKey(),
		NewAlgorithm: Algorithm_ALGORITHM_ED25519,
	}}

	tests := []struct {
		name    string
		tx      *Transaction
		wantErr error
	}{
		// --- happy paths ---
		{
			name: "valid register transaction with signature",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      validRegisterBody,
			},
			wantErr: nil,
		},
		{
			name: "valid revoke transaction with signature",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      validRevokeBody,
			},
			wantErr: nil,
		},
		{
			name: "valid rotate transaction with signature",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      validRotateBody,
			},
			wantErr: nil,
		},
		{
			name: "valid transaction with empty signature",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: nil,
				Body:      validRegisterBody,
			},
			wantErr: nil,
		},
		{
			name: "valid transaction with chain id at max length",
			tx: &Transaction{
				ChainId:   strings.Repeat("a", MaxChainIDLength),
				Signature: validSig(),
				Body:      validRegisterBody,
			},
			wantErr: nil,
		},

		// --- errors: nil ---
		{
			name:    "nil transaction",
			tx:      nil,
			wantErr: ErrNilTransaction,
		},

		// --- errors: signature ---
		{
			name: "signature wrong size",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: make([]byte, Ed25519SigSize-1),
				Body:      validRegisterBody,
			},
			wantErr: ErrInvalidSignatureSize,
		},
		{
			name: "signature too long",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: make([]byte, Ed25519SigSize+1),
				Body:      validRegisterBody,
			},
			wantErr: ErrInvalidSignatureSize,
		},

		// --- errors: chain id ---
		{
			name: "empty chain id",
			tx: &Transaction{
				ChainId:   "",
				Signature: validSig(),
				Body:      validRegisterBody,
			},
			wantErr: ErrInvalidChainID,
		},
		{
			name: "chain id too long",
			tx: &Transaction{
				ChainId:   strings.Repeat("a", MaxChainIDLength+1),
				Signature: validSig(),
				Body:      validRegisterBody,
			},
			wantErr: ErrInvalidChainID,
		},

		// --- errors: body ---
		{
			name: "nil body",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      nil,
			},
			wantErr: ErrNilTransactionBody,
		},
		{
			name: "register body wrapper with nil inner",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      &Transaction_Register{Register: nil},
			},
			wantErr: ErrNilRegisterTx,
		},
		{
			name: "revoke body wrapper with nil inner",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      &Transaction_Revoke{Revoke: nil},
			},
			wantErr: ErrNilRevokeTx,
		},
		{
			name: "rotate body wrapper with nil inner",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      &Transaction_Rotate{Rotate: nil},
			},
			wantErr: ErrNilRotateTx,
		},

		// --- errors: inner validation (delegated) ---
		{
			name: "invalid register inner",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      &Transaction_Register{Register: &RegisterTx{Certificate: nil}},
			},
			wantErr: ErrNilCertificate,
		},
		{
			name: "invalid revoke inner (nonce zero)",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body:      &Transaction_Revoke{Revoke: &RevokeTx{Domain: "example.com", Nonce: 0}},
			},
			wantErr: ErrNonceEqualZero,
		},
		{
			name: "invalid rotate inner (bad key)",
			tx: &Transaction{
				ChainId:   "mainnet",
				Signature: validSig(),
				Body: &Transaction_Rotate{Rotate: &RotateTx{
					Domain:       "example.com",
					Nonce:        1,
					NewPublicKey: make([]byte, 10),
					NewAlgorithm: Algorithm_ALGORITHM_ED25519,
				}},
			},
			wantErr: ErrInvalidKeySize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tx.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no err, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
