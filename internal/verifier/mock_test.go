package verifier

import (
	"context"
	"errors"
	"testing"
)

func TestMockVerifier_AllowAll(t *testing.T) {
	v := AllowAllVerifier()
	if err := v.Verify(context.Background(), registerTx(t, "anything.com", newPub(t))); err != nil {
		t.Fatalf("AllowAll Verify = %v, want nil", err)
	}
}

func TestMockVerifier_AllowList(t *testing.T) {
	v := &MockVerifier{Allowed: map[string]bool{"ok.com": true}}

	if err := v.Verify(context.Background(), registerTx(t, "ok.com", newPub(t))); err != nil {
		t.Fatalf("allowed domain Verify = %v, want nil", err)
	}
	if err := v.Verify(context.Background(), registerTx(t, "blocked.com", newPub(t))); !errors.Is(err, ErrDomainNotAllowed) {
		t.Fatalf("blocked domain Verify = %v, want ErrDomainNotAllowed", err)
	}
}

func TestMockVerifier_ForcedError(t *testing.T) {
	sentinel := errors.New("boom")
	v := &MockVerifier{AllowAll: true, Err: sentinel}
	if err := v.Verify(context.Background(), registerTx(t, "ok.com", newPub(t))); !errors.Is(err, sentinel) {
		t.Fatalf("forced-error Verify = %v, want sentinel", err)
	}
}

func TestMockVerifier_NilTx(t *testing.T) {
	if err := AllowAllVerifier().Verify(context.Background(), nil); !errors.Is(err, ErrNilRegisterTx) {
		t.Fatalf("Verify(nil) = %v, want ErrNilRegisterTx", err)
	}
}

func TestSystemResolver_NotNil(t *testing.T) {
	if SystemResolver() == nil {
		t.Fatal("SystemResolver returned nil")
	}
}

// TestNewDNSVerifier_Defaults covers the zero-timeout and nil-logger fallbacks.
func TestNewDNSVerifier_Defaults(t *testing.T) {
	v := NewDNSVerifier(fakeResolver{}, testChainID, 0, nil)
	if v.timeout != DefaultTimeout {
		t.Fatalf("timeout = %v, want default %v", v.timeout, DefaultTimeout)
	}
	if v.logger == nil {
		t.Fatal("logger not defaulted")
	}
}
