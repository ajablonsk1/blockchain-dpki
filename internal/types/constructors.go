package types

func NewCertificate(domain string, pubKey []byte, algo Algorithm, validFrom int64) (*Certificate, error) {
	cert := &Certificate{
		Domain:    domain,
		PublicKey: pubKey,
		Algorithm: algo,
		ValidFrom: validFrom,
	}

	if err := cert.Validate(); err != nil {
		return nil, err
	}

	return cert, nil
}

func NewRegisterTx(cert *Certificate, chainID string) (*Transaction, error) {
	tx := &Transaction{
		Body: &Transaction_Register{
			&RegisterTx{
				Certificate: cert,
			},
		},
		ChainId: chainID,
	}

	if err := tx.Validate(); err != nil {
		return nil, err
	}

	return tx, nil
}

func NewRevokeTx(domain string, nonce uint64, reason, chainID string) (*Transaction, error) {
	tx := &Transaction{
		Body: &Transaction_Revoke{
			&RevokeTx{
				Domain: domain,
				Nonce:  nonce,
				Reason: reason,
			},
		},
		ChainId: chainID,
	}

	if err := tx.Validate(); err != nil {
		return nil, err
	}

	return tx, nil
}

func NewRotateTx(domain string, nonce uint64, newPubKey []byte, newAlgo Algorithm, chainID string) (*Transaction, error) {
	tx := &Transaction{
		Body: &Transaction_Rotate{
			&RotateTx{
				Domain:       domain,
				Nonce:        nonce,
				NewPublicKey: newPubKey,
				NewAlgorithm: newAlgo,
			},
		},
		ChainId: chainID,
	}

	if err := tx.Validate(); err != nil {
		return nil, err
	}

	return tx, nil
}
