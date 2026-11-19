package cloudflare

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestPauseOwnerRoundTrip(t *testing.T) {
	for _, name := range []string{"example.org", "www.example.org", "multi.owner.example.org"} {
		paused, err := pauseOwner(name, "example.org", "A", "disabled")
		if err != nil || paused == name {
			t.Fatal(name, paused, err)
		}
		twice, err := pauseOwner(paused, "example.org", "A", "disabled")
		if err != nil || twice != paused {
			t.Fatal(twice, err)
		}
		back, err := pauseOwner(paused, "example.org", "A", "enabled")
		if err != nil || back != name {
			t.Fatal(name, back, err)
		}
	}
	for _, tc := range []struct{ name, typ string }{{"example.org", "NS"}, {"example.org", "SOA"}, {"outside.test", "A"}, {"__root__.example.org", "TXT"}, {strings.Repeat("a", 61) + ".example.org", "A"}} {
		if _, err := pauseOwner(tc.name, "example.org", tc.typ, "disabled"); err == nil {
			t.Fatalf("accepted unsafe owner %+v", tc)
		}
	}
}

func TestAdvancedSettingChangesOnlySelectedField(t *testing.T) {
	for _, tc := range []struct{ field, value, want string }{{"status", "disabled", "name"}, {"remark", "test", "comment"}, {"line", "1", "proxied"}} {
		t.Run(tc.field, func(t *testing.T) {
			writes := 0
			client := localClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "GET" && r.URL.Path == "/zones/"+testZone {
					fmt.Fprintf(w, `{"success":true,"result":{"id":%q,"name":"example.org"}}`, testZone)
					return
				}
				if r.URL.Path != "/zones/"+testZone+"/dns_records/"+testRecord {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				if r.Method == "GET" {
					fmt.Fprintf(w, `{"success":true,"result":{"id":%q,"type":"A","name":"www.example.org","content":"1.1.1.1","ttl":300,"proxiable":true}}`, testRecord)
					return
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if r.Method != "PATCH" || len(body) != 1 || body[tc.want] == nil {
					t.Errorf("unexpected write: %s %v", r.Method, body)
				}
				if tc.field == "status" && body["name"] != "www_pause.example.org" {
					t.Errorf("unexpected paused name: %v", body)
				}
				writes++
				fmt.Fprintf(w, `{"success":true,"result":{"id":%q}}`, testRecord)
			})
			if err := client.SetBatchAttribute(t.Context(), testZone, testRecord, tc.field, tc.value); err != nil || writes != 1 {
				t.Fatal(writes, err)
			}
		})
	}
}
