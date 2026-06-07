// Command dpkid runs a single-node DPKI blockchain on top of CometBFT.
//
// Usage:
//
//	dpkid init  [--home DIR] [--chain-id ID]   # generate config, keys and genesis
//	dpkid start [--home DIR]                    # start the node
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
	case "init":
		err = runInit(os.Args[2:])
	case "start":
		err = runStart(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "dpkid %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dpkid — single-node DPKI blockchain

Commands:
  init   Generate CometBFT config, validator/node keys and genesis
  start  Start the node and begin producing blocks

Run "dpkid <command> --help" for command-specific flags.
`)
}

// defaultHome returns the CometBFT home directory, honoring $CMTHOME and falling
// back to $HOME/.dpkid.
func defaultHome() string {
	if h := os.Getenv("CMTHOME"); h != "" {
		return h
	}
	return os.ExpandEnv("$HOME/.dpkid")
}
