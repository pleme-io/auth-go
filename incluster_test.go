package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"testing"
)

// InClusterProfile.InClusterToken reads the SA JWT, applies the base64 quirk,
// and maps a missing file to ErrNotInCluster.
func TestInClusterProfile_InClusterToken(t *testing.T) {
	const jwt = "eyJ.sa.jwt"
	cases := []struct {
		name    string
		profile InClusterProfile
		read    func(string) ([]byte, error)
		want    string
		wantErr error
	}{
		{
			name:    "raw token at default path",
			profile: InClusterProfile{},
			read:    func(p string) ([]byte, error) { return []byte(jwt + "\n"), nil },
			want:    jwt,
		},
		{
			name:    "base64 quirk",
			profile: InClusterProfile{Base64: true},
			read:    func(string) ([]byte, error) { return []byte(jwt), nil },
			want:    base64.StdEncoding.EncodeToString([]byte(jwt)),
		},
		{
			name:    "not in cluster",
			profile: InClusterProfile{},
			read:    func(string) ([]byte, error) { return nil, os.ErrNotExist },
			wantErr: ErrNotInCluster,
		},
		{
			name:    "empty file",
			profile: InClusterProfile{},
			read:    func(string) ([]byte, error) { return []byte("  \n"), nil },
			wantErr: ErrNotInCluster,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.profile
			p.readFile = c.read
			got, err := p.InClusterToken()
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("token = %q, want %q", got, c.want)
			}
		})
	}
}

// The default token path is the well-known projected-SA mount.
func TestInCluster_DefaultPath(t *testing.T) {
	var sawPath string
	p := InClusterProfile{readFile: func(path string) ([]byte, error) {
		sawPath = path
		return []byte("jwt"), nil
	}}
	if _, err := p.InClusterToken(); err != nil {
		t.Fatal(err)
	}
	if sawPath != DefaultServiceAccountTokenPath {
		t.Errorf("read path = %q, want %q", sawPath, DefaultServiceAccountTokenPath)
	}
}

// InClusterResolver builds a Session over the SA JWT and reports KindK8s; a
// missing token surfaces ErrNotInCluster at Resolve.
func TestInClusterResolver(t *testing.T) {
	var _ AuthResolver = (*InClusterResolver)(nil)

	present := withInClusterReadFile(func(string) ([]byte, error) { return []byte("sa-jwt"), nil })
	r := NewInClusterResolver(present, WithInClusterTokenPath("/custom/token"))
	if r.Kinds()[0] != KindK8s {
		t.Errorf("Kinds = %v, want [k8s]", r.Kinds())
	}
	if r.Profile().TokenPath != "/custom/token" {
		t.Errorf("profile path = %q, want /custom/token", r.Profile().TokenPath)
	}
	sess, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sess.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "sa-jwt" {
		t.Errorf("token = %q, want sa-jwt", tok.Value)
	}

	absent := NewInClusterResolver(withInClusterReadFile(func(string) ([]byte, error) {
		return nil, os.ErrNotExist
	}))
	if _, err := absent.Resolve(context.Background()); !errors.Is(err, ErrNotInCluster) {
		t.Fatalf("Resolve(absent) err = %v, want ErrNotInCluster", err)
	}
}

// The base64 quirk option is honoured through the resolver.
func TestInClusterResolver_Base64(t *testing.T) {
	const jwt = "raw-jwt"
	r := NewInClusterResolver(
		WithInClusterBase64(true),
		withInClusterReadFile(func(string) ([]byte, error) { return []byte(jwt), nil }),
	)
	sess, _ := r.Resolve(context.Background())
	tok, _ := sess.Token(context.Background())
	if tok.Value != base64.StdEncoding.EncodeToString([]byte(jwt)) {
		t.Errorf("token = %q, want base64-encoded jwt", tok.Value)
	}
}
