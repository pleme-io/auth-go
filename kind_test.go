package auth

import "testing"

// ParseKind accepts wire strings and friendly aliases, case-insensitively, and
// rejects unknowns.
func TestParseKind(t *testing.T) {
	cases := []struct {
		in   string
		want AuthKind
	}{
		{"api_key", KindAPIKey},
		{"APIKey", KindAPIKey},
		{"access-key", KindAPIKey},
		{"aws", KindAWSIAM},
		{"aws_iam", KindAWSIAM},
		{"Azure", KindAzureAD},
		{"gcp", KindGCP},
		{"kubernetes", KindK8s},
		{"oidc", KindOIDC},
		{"saml", KindSAML},
		{"certificate", KindCert},
		{"email", KindEmail},
		{"ldap", KindLDAP},
		{"uid", KindUniversalIdentity},
	}
	for _, c := range cases {
		got, err := ParseKind(c.in)
		if err != nil {
			t.Errorf("ParseKind(%q) err = %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseKind(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := ParseKind("totally-unknown"); err == nil {
		t.Error("ParseKind(unknown) = nil err, want error")
	}
}

// Valid + AllKinds agree: every AllKinds entry is Valid, and a junk kind is not.
func TestAuthKind_ValidAndAll(t *testing.T) {
	all := AllKinds()
	if len(all) == 0 {
		t.Fatal("AllKinds is empty")
	}
	for _, k := range all {
		if !k.Valid() {
			t.Errorf("AllKinds entry %q reports !Valid", k)
		}
	}
	if AuthKind("junk").Valid() {
		t.Error(`AuthKind("junk").Valid() = true, want false`)
	}
	// The wire string round-trips.
	if KindAPIKey.String() != "api_key" {
		t.Errorf("KindAPIKey.String() = %q, want api_key", KindAPIKey)
	}
}
