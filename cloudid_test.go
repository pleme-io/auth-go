package auth

import (
	"context"
	"errors"
	"testing"
)

// Cloud → AuthKind mapping is total and round-trips for the three families.
func TestCloud_Kind(t *testing.T) {
	cases := []struct {
		cloud Cloud
		want  AuthKind
	}{
		{CloudAWS, KindAWSIAM},
		{CloudAzure, KindAzureAD},
		{CloudGCP, KindGCP},
		{Cloud("nope"), ""},
	}
	for _, c := range cases {
		t.Run(c.cloud.String(), func(t *testing.T) {
			if got := c.cloud.Kind(); got != c.want {
				t.Errorf("Cloud(%q).Kind() = %q, want %q", c.cloud, got, c.want)
			}
		})
	}
}

// CloudIdentityFunc carries a func as a provider; nil func → ErrNoCloudIdentity.
func TestCloudIdentityFunc(t *testing.T) {
	var _ CloudIdentityProvider = (*CloudIdentityFunc)(nil)

	cases := []struct {
		name    string
		cloud   Cloud
		fn      func(context.Context) (string, error)
		want    string
		wantErr error
	}{
		{
			name:  "aws blob",
			cloud: CloudAWS,
			fn:    func(context.Context) (string, error) { return "base64-aws-blob", nil },
			want:  "base64-aws-blob",
		},
		{
			name:    "nil fn",
			cloud:   CloudGCP,
			fn:      nil,
			wantErr: ErrNoCloudIdentity,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewCloudIdentityFunc(c.cloud, c.fn)
			if p.Cloud() != c.cloud {
				t.Errorf("Cloud() = %q, want %q", p.Cloud(), c.cloud)
			}
			got, err := p.Identity(context.Background())
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("Identity err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("Identity = %q, want %q", got, c.want)
			}
		})
	}
}
