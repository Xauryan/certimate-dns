package dnsutil

import (
	"errors"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestMXParts(t *testing.T) {
	p := 10
	for _, tc := range []struct {
		content  string
		field    *int
		expected int
		invalid  bool
	}{
		{"mx.example.test.", nil, 20, false},
		{"mx.example.test.", &p, 10, false},
		{"10 mx.example.test.", &p, 10, false},
		{"0 mx.example.test.", nil, 0, false},
		{"11 mx.example.test.", &p, 0, true},
		{"51 mx.example.test.", nil, 0, true},
		{"11 mx.example.test. extra", nil, 0, true},
	} {
		target, preference, err := MXParts(tc.content, tc.field, 20, 50)
		if tc.invalid {
			if !errors.Is(err, dns.ErrInvalidDNSRequest) {
				t.Errorf("accepted %q", tc.content)
			}
			continue
		}
		if err != nil || target != "mx.example.test." || preference != tc.expected {
			t.Errorf("MXParts(%q) returned %q %d %v", tc.content, target, preference, err)
		}
	}
}
