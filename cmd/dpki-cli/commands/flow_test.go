package commands

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/client"
)

// TestFullDomainLifecycle drives the whole user workflow against a mock node:
// register -> lookup (+proof bundle) -> verify -> verify-offline -> rotate ->
// revoke, asserting on the outputs the user would see.
func TestFullDomainLifecycle(t *testing.T) {
	n := startMockNode(t)
	dir := t.TempDir()
	const domain = "test.example.com"

	ownerKey, ownerPub := generateKey(t, dir, "owner.priv")

	// Register.
	out, _, err := runCLI(t, "register", "--domain", domain, "--keyfile", ownerKey, "--node", n.URL, "--skip-challenge")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !strings.Contains(out, "registered successfully") {
		t.Errorf("register output:\n%s", out)
	}
	if n.TxsCommitted() != 1 {
		t.Fatalf("node committed %d txs, want 1", n.TxsCommitted())
	}

	// Lookup with proof and certificate export.
	proofFile := filepath.Join(dir, "proof.json")
	certFile := filepath.Join(dir, "cert.json")
	out, _, err = runCLI(t, "lookup", "--domain", domain, "--node", n.URL,
		"--save-proof", proofFile, "--save-cert", certFile)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	for _, want := range []string{"Status:       Active", ownerPub, "verified locally"} {
		if !strings.Contains(out, want) {
			t.Errorf("lookup output misses %q:\n%s", want, out)
		}
	}

	// Lookup in JSON.
	out, _, err = runCLI(t, "lookup", "--domain", domain, "--node", n.URL, "--output-format", "json")
	if err != nil {
		t.Fatalf("lookup --output-format json: %v", err)
	}
	if !strings.Contains(out, `"present": true`) || !strings.Contains(out, `"verified": true`) {
		t.Errorf("json lookup output:\n%s", out)
	}

	// Online verification against "two" nodes.
	out, _, err = runCLI(t, "verify", "--domain", domain, "--nodes", n.URL+","+n.URL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out, "verified by 2/2") {
		t.Errorf("verify output:\n%s", out)
	}

	// Offline verification against the recorded root...
	bundle, err := client.LoadProofBundle(proofFile)
	if err != nil {
		t.Fatalf("load saved bundle: %v", err)
	}
	out, _, err = runCLI(t, "verify-offline", "--proof", proofFile, "--root", bundle.AppHash, "--cert", certFile)
	if err != nil {
		t.Fatalf("verify-offline: %v", err)
	}
	if !strings.Contains(out, "proof valid") || !strings.Contains(out, "matches the proven state") {
		t.Errorf("verify-offline output:\n%s", out)
	}

	// ...and rejection for a root the proof does not commit to.
	badRoot := strings.Repeat("00", 32)
	if _, _, err := runCLI(t, "verify-offline", "--proof", proofFile, "--root", badRoot); err == nil {
		t.Fatal("verify-offline accepted a wrong root")
	}

	// Rotate to a new key; the old key signs.
	newKey, newPub := generateKey(t, dir, "new.priv")
	out, _, err = runCLI(t, "rotate", "--domain", domain, "--keyfile", ownerKey, "--new-keyfile", newKey, "--node", n.URL)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !strings.Contains(out, newPub) {
		t.Errorf("rotate output misses the new public key:\n%s", out)
	}

	// The old key must no longer authorize mutations.
	if _, _, err := runCLI(t, "revoke", "--domain", domain, "--keyfile", ownerKey, "--node", n.URL); err == nil {
		t.Fatal("revoke signed with the rotated-out key succeeded")
	}

	// Revoke with the new key.
	out, _, err = runCLI(t, "revoke", "--domain", domain, "--keyfile", newKey, "--node", n.URL, "--reason", "key compromised")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !strings.Contains(out, "revoked") {
		t.Errorf("revoke output:\n%s", out)
	}

	// Lookup now shows the revocation.
	out, _, err = runCLI(t, "lookup", "--domain", domain, "--node", n.URL)
	if err != nil {
		t.Fatalf("lookup after revoke: %v", err)
	}
	if !strings.Contains(out, "REVOKED") || !strings.Contains(out, "key compromised") {
		t.Errorf("lookup after revoke output:\n%s", out)
	}

	// Revoking again must fail client-side with a readable message.
	_, _, err = runCLI(t, "revoke", "--domain", domain, "--keyfile", newKey, "--node", n.URL)
	if err == nil || !strings.Contains(err.Error(), "already revoked") {
		t.Errorf("second revoke error = %v, want 'already revoked'", err)
	}
}

func TestLookupAbsentDomain(t *testing.T) {
	n := startMockNode(t)

	out, _, err := runCLI(t, "lookup", "--domain", "absent.example.com", "--node", n.URL)
	if err != nil {
		t.Fatalf("lookup absent: %v", err)
	}
	if !strings.Contains(out, "not registered") || !strings.Contains(out, "non-inclusion proof verified") {
		t.Errorf("lookup absent output:\n%s", out)
	}
}

func TestRegisterDuplicateRejectedByNode(t *testing.T) {
	n := startMockNode(t)
	dir := t.TempDir()
	key, _ := generateKey(t, dir, "owner.priv")
	const domain = "dup.example.com"

	if _, _, err := runCLI(t, "register", "--domain", domain, "--keyfile", key, "--node", n.URL, "--skip-challenge"); err != nil {
		t.Fatalf("first register: %v", err)
	}

	_, _, err := runCLI(t, "register", "--domain", domain, "--keyfile", key, "--node", n.URL, "--skip-challenge")
	if err == nil {
		t.Fatal("duplicate register succeeded")
	}
	if !strings.Contains(err.Error(), "rejected by CheckTx") {
		t.Errorf("duplicate register error = %v, want a CheckTx rejection", err)
	}
	if n.TxsCommitted() != 1 {
		t.Errorf("node committed %d txs, want 1 (the duplicate must not land in a block)", n.TxsCommitted())
	}
}

func TestRevokeUnregisteredDomain(t *testing.T) {
	n := startMockNode(t)
	dir := t.TempDir()
	key, _ := generateKey(t, dir, "owner.priv")

	_, _, err := runCLI(t, "revoke", "--domain", "ghost.example.com", "--keyfile", key, "--node", n.URL)
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("revoke of unregistered domain error = %v, want 'not registered'", err)
	}
}

// TestVerboseShowsSignBytes guards the -v debugging aid: sign bytes and the
// node's raw verdict must land on stderr.
func TestVerboseShowsSignBytes(t *testing.T) {
	n := startMockNode(t)
	dir := t.TempDir()
	key, _ := generateKey(t, dir, "owner.priv")

	_, errOut, err := runCLI(t, "register", "--domain", "v.example.com", "--keyfile", key,
		"--node", n.URL, "--skip-challenge", "-v")
	if err != nil {
		t.Fatalf("register -v: %v", err)
	}
	for _, want := range []string{"sign bytes", "signature:", "check_tx code=0"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("verbose stderr misses %q:\n%s", want, errOut)
		}
	}
}
