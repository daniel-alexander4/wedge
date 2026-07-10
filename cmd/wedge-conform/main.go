// Command wedge-conform is the wedge protocol conformance harness: it drives
// an RP implementation over HTTP in the authenticator role and asserts every
// wire-observable RP requirement of docs/wedge-spec-v1.md. See
// docs/wedge-conformance.md for the bootstrap contract.
//
// Typical run against a reference-shape RP (any wedge-rp SDK or wedge-web):
//
//	wedge-conform --target http://127.0.0.1:9413 --key ./conform_ed25519 --user conform
//
// Exit status 0 = every wire-observable MUST passed.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/daniel-alexander4/wedge/internal/conform"
)

// version is set at build time via -ldflags "-X main.version=…".
var version = "dev"

func main() {
	log.SetFlags(0)
	log.SetPrefix("wedge-conform: ")

	target := flag.String("target", "", "RP origin under test, e.g. http://127.0.0.1:9413 (required)")
	user := flag.String("user", "", "username the harness key is registered under (optional; enables username-flow start)")
	keyPath := flag.String("key", "", "private key file registered with the RP (default: generate a throwaway and prompt)")
	startCmd := flag.String("start-cmd", "", "command printing a request_id or wedge:// link, for RPs with a non-reference start shape")
	jsonOut := flag.Bool("json", false, "emit the machine-readable JSON report")
	probes := flag.Bool("probe-limits", false, "also probe rate limiting and concurrency bounds (deliberately trips the target)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("wedge-conform %s\n", version)
		return
	}
	if *target == "" {
		log.Fatal("--target is required")
	}

	var key *conform.KeyPair
	var err error
	if *keyPath != "" {
		key, err = conform.LoadKey(*keyPath)
		if err != nil {
			log.Fatalf("--key: %v", err)
		}
	} else {
		dir, derr := os.MkdirTemp("", "wedge-conform-key-")
		if derr != nil {
			log.Fatal(derr)
		}
		defer os.RemoveAll(dir)
		key, err = conform.GenerateKey(dir)
		if err != nil {
			log.Fatalf("generating throwaway key: %v", err)
		}
		fmt.Fprintf(os.Stderr, `A throwaway key was generated. Register this public key with the target RP
(the wedge-rp demos take --user NAME:PUBKEY_PATH / WEDGE_DEMO_USERS), then
press Enter to start the run:

  %s

`, key.PublicKey)
		bufio.NewReader(os.Stdin).ReadString('\n')
	}

	s, err := conform.NewSession(*target, *user, key, *startCmd)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	rep := conform.Run(s, version, *probes)
	if *jsonOut {
		if err := rep.WriteJSON(os.Stdout); err != nil {
			log.Fatal(err)
		}
	} else {
		rep.WriteText(os.Stdout)
	}
	if !rep.Passed() {
		os.Exit(1)
	}
}
