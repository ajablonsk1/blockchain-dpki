package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

func Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func Fingerprint(pubKey []byte) string {
	hash := Hash(pubKey)
	return hex.EncodeToString(hash)
}
