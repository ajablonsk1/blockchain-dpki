package types

import "testing"

func TestTransaction_BodyType(t *testing.T) {
	tests := []struct {
		name string
		tx   *Transaction
		want string
	}{
		{"nil tx", nil, ""},
		{"empty body", &Transaction{}, ""},
		{
			"register",
			&Transaction{Body: &Transaction_Register{Register: &RegisterTx{}}},
			"register",
		},
		{
			"revoke",
			&Transaction{Body: &Transaction_Revoke{Revoke: &RevokeTx{}}},
			"revoke",
		},
		{
			"rotate",
			&Transaction{Body: &Transaction_Rotate{Rotate: &RotateTx{}}},
			"rotate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tx.BodyType()
			if got != tt.want {
				t.Fatalf("BodyType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTransaction_GetDomainFromBody(t *testing.T) {
	tests := []struct {
		name string
		tx   *Transaction
		want string
	}{
		{"nil tx", nil, ""},
		{"empty body", &Transaction{}, ""},
		{
			"register",
			&Transaction{
				Body: &Transaction_Register{
					Register: &RegisterTx{
						Certificate: &Certificate{Domain: "example.com"},
					},
				},
			},
			"example.com",
		},
		{
			"register with nil cert",
			&Transaction{
				Body: &Transaction_Register{
					Register: &RegisterTx{Certificate: nil},
				},
			},
			"", // GetCertificate() na nil-Register → nil → GetDomain() → ""
		},
		{
			"revoke",
			&Transaction{
				Body: &Transaction_Revoke{
					Revoke: &RevokeTx{Domain: "test.com"},
				},
			},
			"test.com",
		},
		{
			"rotate",
			&Transaction{
				Body: &Transaction_Rotate{
					Rotate: &RotateTx{Domain: "rotate.com"},
				},
			},
			"rotate.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tx.GetDomainFromBody()
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
