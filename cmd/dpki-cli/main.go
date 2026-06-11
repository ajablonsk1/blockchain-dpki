// Command dpki-cli is the client of the DPKI blockchain.
//
// It manages Ed25519 keypairs, registers, rotates and revokes domain
// certificates, and looks up certificates together with Merkle proofs that can
// be verified offline against a trusted app hash. Run "dpki-cli --help" for the
// full command list.
package main

import (
	"os"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/commands"
)

func main() {
	if err := commands.NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
