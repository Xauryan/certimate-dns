package registrarutil

import "testing"

func TestCAAPresentation(t *testing.T) {
	for _, value := range []string{"", "issuer.test; account=42", "quote \" and backslash \\", "a\n\tb", "运维", string([]byte{0, 127, 255})} {
		flag, tag, got, err := ParseCAA(FormatCAA(128, "issuewild", value))
		if err != nil || flag != 128 || tag != "issuewild" || got != value {
			t.Fatalf("CAA round trip failed for %q: %q, %v", value, got, err)
		}
	}
	for input, expected := range map[string]string{`0 issue "test\032name\;\092"`: "test name;\\", "0\tiodef\tmailto:ops@example.test": "mailto:ops@example.test", `0 issue ca.test; property=one\ two`: "ca.test; property=one two"} {
		_, _, got, err := ParseCAA(input)
		if err != nil || got != expected {
			t.Fatalf("parse %q: got %q, %v", input, got, err)
		}
	}
	for _, input := range []string{`0 issue "\256"`, `0 issue "\3"`, `0 issue "x\"`, `0 issue "x" extra`, `512 issue issuer`} {
		if _, _, _, err := ParseCAA(input); err == nil {
			t.Fatalf("accepted malformed CAA %q", input)
		}
	}
}
