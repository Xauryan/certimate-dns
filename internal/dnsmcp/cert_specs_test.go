package dnsmcp

import "testing"

func TestCertificateProviderKeySpecs(t *testing.T) {
	for _, tc := range []struct {
		provider, previous, kind, size, want string
		ok                                   bool
	}{
		{"aliyun", "", "RSA", "3072", "RSA3072", true},
		{"ucloud", "", "ECC", "384", "EC384", true},
		{"ucloud", "", "RSA", "3072", "RSA3072", true},
		{"aliyun", "", "ECC", "384", "EC384", false},
		{"tencentcloud", "", "RSA", "3072", "RSA3072", false},
		{"volcengine", "", "ECC", "384", "EC384", false},
		{"ucloud", "EC384", "ECC", "", "EC384", true},
		{"aliyun", "RSA3072", "", "", "RSA3072", true},
		{"ucloud", "RSA3072", "ECC", "", "EC256", true},
	} {
		args := object{}
		if tc.kind != "" {
			args["keytype"] = tc.kind
		}
		if tc.size != "" {
			args["keysize"] = tc.size
		}
		value, ok := certKeySpec(args, tc.previous, tc.provider)
		if value != tc.want || ok != tc.ok {
			t.Errorf("%s %v with %s: got %s/%v", tc.provider, args, tc.previous, value, ok)
		}
	}
}

func TestBtwinUsesWindowsPanelCredential(t *testing.T) {
	if deploymentAccountSpecs["btwin"].native != "baotapanelgo" || deploymentAccountSpecs["btpanel"].native != "baotapanel" {
		t.Fatal("incorrect Baota provider mapping")
	}
}
