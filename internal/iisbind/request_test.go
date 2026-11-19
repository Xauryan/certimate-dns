package iisbind

import (
	"strings"
	"testing"
)

func TestAuthorizeExactSNIOnly(t *testing.T) {
	const policy = "# approved bindings\r\n site.example.test\r\nmail.example.test:8443 create\r\n"
	for _, test := range []struct {
		target         string
		absent, create bool
	}{
		{"Site.Example.Test.:443", false, false},
		{"mail.example.test:8443", false, true},
		{"mail.example.test", true, false},
		{"other.site.example.test", true, false},
		{"*.example.test", true, false},
		{"192.0.2.55", true, false},
		{"site.example.test:443;whoami", true, false},
		{"site.example.test:65536", true, false},
	} {
		if create, err := Authorize(policy, test.target); create != test.create || (err != nil) != test.absent {
			t.Fatalf("incorrect policy result for %s: %v, %v", test.target, create, err)
		}
	}
	for _, bad := range []string{"site.example.test.:443 create", "malformed", "other.example.test execute"} {
		if _, err := Authorize(policy+bad, "site.example.test"); err == nil {
			t.Fatalf("accepted malformed or duplicate policy entry %q", bad)
		}
	}
}

func TestReadRejectsMalformedOrOversizedRequest(t *testing.T) {
	for _, input := range []string{
		`{"target":"site.example.test","command":"unused"}`,
		`{"target":"site.example.test"}{}`,
		strings.Repeat(" ", MaxRequest+1),
	} {
		if _, err := Read(strings.NewReader(input)); err == nil {
			t.Fatal("unexpected request accepted")
		}
	}
}
