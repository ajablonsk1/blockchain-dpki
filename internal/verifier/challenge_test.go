package verifier

import (
	"encoding/hex"
	"testing"
)

func TestChallengeValue_Deterministic(t *testing.T) {
	pub := []byte("public-key-bytes")
	a := ChallengeValue("example.com", pub, "chain-1")
	b := ChallengeValue("example.com", pub, "chain-1")
	if a != b {
		t.Fatalf("non-deterministic: %q != %q", a, b)
	}
}

func TestChallengeValue_Format(t *testing.T) {
	v := ChallengeValue("example.com", []byte("k"), "chain-1")
	if len(v) != 64 {
		t.Fatalf("length = %d, want 64 hex chars", len(v))
	}
	if _, err := hex.DecodeString(v); err != nil {
		t.Fatalf("not valid hex: %v", err)
	}
}

func TestChallengeValue_SensitiveToEveryInput(t *testing.T) {
	base := ChallengeValue("example.com", []byte("key-a"), "chain-1")

	cases := map[string]string{
		"different domain":  ChallengeValue("other.com", []byte("key-a"), "chain-1"),
		"different pubkey":  ChallengeValue("example.com", []byte("key-b"), "chain-1"),
		"different chainID": ChallengeValue("example.com", []byte("key-a"), "chain-2"),
	}
	for name, got := range cases {
		if got == base {
			t.Errorf("%s produced the same challenge value", name)
		}
	}
}

// TestChallengeValue_NoConcatenationCollision guards the NUL domain separation:
// ("ab","c") and ("a","bc") must not collide.
func TestChallengeValue_NoConcatenationCollision(t *testing.T) {
	x := ChallengeValue("ab", []byte("c"), "chain")
	y := ChallengeValue("a", []byte("bc"), "chain")
	if x == y {
		t.Fatal("concatenation collision: separators not effective")
	}
}

func TestChallengeName(t *testing.T) {
	if got := ChallengeName("example.com"); got != "_dpki-challenge.example.com" {
		t.Fatalf("ChallengeName = %q", got)
	}
}
