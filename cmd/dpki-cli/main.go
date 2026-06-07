// Command dpki-cli is the client-side helper for the DPKI blockchain.
//
// Usage:
//
//	dpki-cli challenge       --domain D --pubkey HEX [--chain-id ID]
//	dpki-cli challenge-check --domain D --pubkey HEX [--chain-id ID] [--resolver host:port]
//
// "challenge" prints the DNS TXT record the domain owner must publish to prove
// control; "challenge-check" looks the record up and reports whether it matches.
package main

import (
	"fmt"
	"os"
)

const defaultChainID = "dpki-testnet-1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "challenge":
		err = runChallenge(os.Args[2:])
	case "challenge-check":
		err = runChallengeCheck(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "dpki-cli %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dpki-cli — DPKI client helper

Commands:
  challenge        Print the DNS TXT record to publish for domain ownership
  challenge-check  Look up the challenge record and report whether it matches

Run "dpki-cli <command> --help" for command-specific flags.
`)
}
