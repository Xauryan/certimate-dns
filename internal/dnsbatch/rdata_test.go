package dnsbatch

import (
	"reflect"
	"strings"
	"testing"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

func TestTypedZoneFileRoundTrip(t *testing.T) {
	const origin = "example.test"
	input := `$ORIGIN example.test.
$TTL 300
@ IN MX 10 mail
null IN MX 0 .
_sip._tcp IN SRV 0 10 5060 sip
_no._tcp IN SRV 0 0 0 .
donor IN DNAME to.example.net.
@ IN CAA 128 issue "issuer.test; account=demo"
@ IN URI 50 20 "https://example.test/.well-known/contact"
@ IN SPF "v=spf1 -all"
txt IN TXT "quote:\" slash:\\ tab:\009 utf8:\195\169"
literal IN TXT "cf_tags=literal"
`
	got, err := importZone(input, origin)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 ||
		got[0].Priority == nil || *got[0].Priority != 10 || got[0].Content != "mail.example.test" ||
		got[1].Priority == nil || *got[1].Priority != 0 || got[1].Content != "." ||
		got[2].Content != "0 10 5060 sip.example.test" || got[3].Content != "0 0 0 ." ||
		got[5].Content != `128 issue "issuer.test; account=demo"` ||
		got[6].Priority == nil || *got[6].Priority != 50 || got[6].Content != `20 "https://example.test/.well-known/contact"` ||
		got[8].Content != "quote:\" slash:\\ tab:\t utf8:é" {
		t.Fatalf("unexpected parsed data: %+v", got)
	}
	rows := make([]dns.DNSRecord, 0, len(got))
	for _, c := range got {
		rows = append(rows, dns.DNSRecord{Name: c.Name, Type: c.Type, Content: c.Content, Priority: c.Priority, TTL: c.TTL})
	}
	exported, err := exportZone(rows, origin)
	if err != nil {
		t.Fatal(err)
	}
	again, err := importZone(exported, origin)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("typed round trip changed: %+v", again)
	}
}

func TestFullAndSplitMXAndSRVProjection(t *testing.T) {
	priority, weight := 0, 20
	record := dns.DNSRecord{Type: "MX", Content: "0 mail.example.test", Priority: &priority}
	got, err := exportValue(record, "aliyunesa")
	if err != nil || got != "0 mail.example.test." {
		t.Fatalf("%q %v", got, err)
	}
	record.Priority = nil
	if v, err := exportValue(record, "spaceship"); err != nil || v != got {
		t.Fatalf("%q %v", v, err)
	}
	priority = 9
	record.Priority = &priority
	if _, err := exportValue(record, "aliyunesa"); err == nil {
		t.Fatal("conflicting MX preference accepted")
	}
	record = dns.DNSRecord{Type: "SRV", Content: "9 20 443 mail.example.test", Priority: &priority, Weight: &weight, Line: "0"}
	if v, err := exportValue(record, "aliyunesa"); err != nil || v != "9 20 443 mail.example.test." {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := exportValue(record, "goedge"); err == nil {
		t.Fatal("provider routing weight dropped")
	}
	record.Weight = nil
	record.Line = ""
	priority = 12
	if _, err := exportValue(record, "cloudflare"); err == nil {
		t.Fatal("conflicting SRV priority accepted")
	}
}

func TestValidationAndExplicitMetadataErrors(t *testing.T) {
	for _, tcase := range []Change{
		{Type: "SRV", Content: "10 0 65536 host.example.test"},
		{Type: "CAA", Content: `0 issue "test" ; discarded`},
		{Type: "URI", Content: "5 \"target\"\n$ORIGIN ."},
		{Type: "CAA", Content: `256 issue "unsupported flag"`},
		{Type: "URI", Content: `bad "target"`},
		{Type: "MX", Content: "70000 mail.test"},
		{Type: "REDIRECT_URL", Content: "file:///local.txt"},
		{Type: "FORWARD_URL", Content: "https://"},
		{Type: "APP", Content: "single"},
		{Type: "UNKNOWN", Content: "data"},
	} {
		if validateData(tcase) == nil {
			t.Errorf("accepted malformed %s", tcase.Type)
		}
	}
	for _, tcase := range []dns.DNSRecord{
		{Type: "A", Content: "127.0.0.1", Line: "custom"},
		{Type: "TXT", Content: "value", Description: "display note"},
		{Type: "A", Content: "127.0.0.1", Status: "disabled"},
		{Type: "TXT", Content: strings.Repeat("x", 256)},
		{Type: "APP", Content: "app class payload"},
		{Type: "ALIAS", Content: "target.example.test"},
	} {
		if _, err := exportValue(tcase, ""); err == nil {
			t.Errorf("silently exported %s", tcase.Type)
		}
	}
}

func TestCanonicalContent(t *testing.T) {
	p := 10
	for _, pair := range [][2]Change{
		{{Type: "MX", Content: "010 Mail.Example.test."}, {Type: "MX", Content: "mail.example.test", Priority: &p}},
		{{Type: "SRV", Content: "0 00 443 Target.Example.test."}, {Type: "SRV", Content: "0 0 443 target.example.test"}},
		{{Type: "CAA", Content: "0 issue issuer.test"}, {Type: "CAA", Content: `0 issue "issuer.test"`}},
		{{Type: "URI", Content: `5 "https://www.example.test/Upper"`, Priority: &p}, {Type: "URI", Content: "5 https://www.example.test/Upper"}},
	} {
		if canonicalContent(pair[0]) != canonicalContent(pair[1]) {
			t.Errorf("different projections for %s", pair[0].Type)
		}
	}
	if got := canonicalContent(Change{Type: "MX", Content: "Mail.Example.test"}); got != "mail.example.test" {
		t.Fatal("unspecified preference was assumed")
	}
	if got := canonicalContent(Change{Type: "TXT", Content: "Mixed Case"}); got != "Mixed Case" {
		t.Fatal("TXT value changed")
	}
}
