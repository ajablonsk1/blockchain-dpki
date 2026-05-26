// Package types defines the core data types for the DPKI system: certificates,
// transactions (Register, Revoke, Rotate), and their syntactic validation.
// Types are generated from .proto files under proto/dpki/v1/.
//
// Validation in this package is limited to syntactic checks (domain format,
// key size, timestamp bounds). Semantic validation — whether a domain already
// exists, whether a signature is authentic, whether a nonce is current — is
// handled by internal/app and internal/crypto.
package types
