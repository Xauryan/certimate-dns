package dnsmanagement

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
)

type editFake struct {
	Provider
	rows          []DNSRecord
	caps          RecordEditCapabilities
	apply         func(*editFake, DNSRecord, RecordInput) (string, error)
	reads, writes int
	badPage       bool
}

func (f *editFake) RecordEditCapabilities() RecordEditCapabilities { return f.caps }
func (f *editFake) DNSRecords(_ context.Context, _ string, n int, filter string) (*DNSPage[DNSRecord], error) {
	if filter != "" {
		return nil, errors.New("unexpected filter")
	}
	f.reads++
	info := PageInfo{Page: n, Total: len(f.rows)}
	begin := min((n-1)*DNSPageSize, len(f.rows))
	end := min(n*DNSPageSize, len(f.rows))
	if f.badPage {
		info.Total++
	}
	return &DNSPage[DNSRecord]{Info: info, Items: slices.Clone(f.rows[begin:end])}, nil
}
func (f *editFake) ReplaceDNSRecord(_ context.Context, _ string, prior DNSRecord, want RecordInput) (string, error) {
	f.writes++
	return f.apply(f, prior, want)
}
func editFixture() (*editFake, DNSRecord, RecordInput) {
	priority, weight := 10, 50
	prior := DNSRecord{ID: "original", Name: "mail.example.test", Type: "MX", Content: "10 MX1.example.test.", TTL: 600, Line: "premium", Priority: &priority, Weight: &weight, Status: "disabled", Description: "preserve"}
	desiredPriority := 20
	want := RecordInput{Name: "new.example.test", Type: "MX", Content: "Mx2.example.test.", TTL: 900, Priority: &desiredPriority, Weight: prior.Weight, Description: prior.Description, Line: prior.Line}
	f := &editFake{rows: []DNSRecord{prior}, caps: RecordEditCapabilities{Rename: true, Retype: true, Priority: true}}
	return f, prior, want
}
func verifyFake(f *editFake, r DNSRecord, w RecordInput) (string, error) {
	return ReplaceVerified(context.Background(), f, "zone", "example.test", r, w, func() bool { return true })
}
func resultRow(prior DNSRecord, w RecordInput) DNSRecord {
	prior.ID = "new-identity"
	prior.Name, prior.Type, prior.TTL = w.Name, w.Type, w.TTL
	prior.Content = "20 mx2.example.test"
	prior.Priority = nil // This provider stores preference inline.
	return prior
}
func TestReplaceVerifiedLostReply(t *testing.T) {
	f, prior, want := editFixture()
	for i := 0; i < DNSPageSize; i++ {
		f.rows = append(f.rows, DNSRecord{ID: fmt.Sprint(i), Type: "TXT", Name: "other.example.test", Content: "data"})
	}
	f.apply = func(f *editFake, r DNSRecord, w RecordInput) (string, error) {
		f.rows[0] = resultRow(r, w)
		return "", errors.New("connection closed after provider accepted the edit")
	}
	got, err := verifyFake(f, prior, want)
	if err != nil || got != "new-identity" || f.reads != 4 || f.writes != 1 {
		t.Fatalf("id=%q error=%v reads=%d writes=%d", got, err, f.reads, f.writes)
	}
}

func TestReplaceVerifiedPresentationTXT(t *testing.T) {
	f, r, w := editFixture()
	r.Type, r.Content, r.Priority = "TXT", `"before"`, nil
	w.Type, w.Content, w.Priority = "TXT", `new \value "text"`, nil
	f.rows[0], f.caps.PresentationTXT = r, true
	f.apply = func(f *editFake, _ DNSRecord, write RecordInput) (string, error) {
		if write.Content != w.Content {
			t.Fatal("verifier rewrote the driver payload")
		}
		f.rows[0].Name, f.rows[0].TTL, f.rows[0].Content = write.Name, write.TTL, `"new \\value \"text\""`
		return r.ID, nil
	}
	if id, err := verifyFake(f, r, w); id != r.ID || err != nil {
		t.Fatalf("id=%q error=%v", id, err)
	}
}

func TestReplaceVerifiedForwardingTypeAlias(t *testing.T) {
	f, r, w := editFixture()
	r.Type, r.Content, r.Priority = "CNAME", "before.example.test.", nil
	w.Type, w.Content, w.Priority = "FORWARD_URL", "https://example.test/", nil
	f.rows[0] = r
	f.apply = func(f *editFake, _ DNSRecord, write RecordInput) (string, error) {
		f.rows[0].Name, f.rows[0].TTL, f.rows[0].Type, f.rows[0].Content = write.Name, write.TTL, "IMPLICIT_URL", write.Content
		return r.ID, nil
	}
	if id, err := verifyFake(f, r, w); id != r.ID || err != nil {
		t.Fatalf("id=%q error=%v", id, err)
	}
}

func TestReplaceVerifiedPreconditions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*editFake, *DNSRecord, *RecordInput)
		want   error
	}{
		{"stale metadata", func(f *editFake, r *DNSRecord, w *RecordInput) { f.rows[0].Description = "changed" }, ErrRecordEditConflict},
		{"previous revision", func(f *editFake, r *DNSRecord, w *RecordInput) { f.rows[0].UpdatedAt = "new revision" }, ErrRecordEditConflict},
		{"existing destination", func(f *editFake, r *DNSRecord, w *RecordInput) { f.rows = append(f.rows, resultRow(*r, *w)) }, ErrRecordEditConflict},
		{"outside zone", func(f *editFake, r *DNSRecord, w *RecordInput) { w.Name = "example.test.other.test" }, ErrInvalidDNSRequest},
		{"unchecked metadata", func(f *editFake, r *DNSRecord, w *RecordInput) { w.Weight = nil }, ErrInvalidDNSRequest},
		{"no rename", func(f *editFake, r *DNSRecord, w *RecordInput) { f.caps.Rename = false }, ErrInvalidDNSRequest},
		{"no priority change", func(f *editFake, r *DNSRecord, w *RecordInput) { f.caps.Priority = false }, ErrInvalidDNSRequest},
		{"missing row", func(f *editFake, r *DNSRecord, w *RecordInput) { f.rows = nil }, ErrRecordEditConflict},
		{"incomplete pages", func(f *editFake, r *DNSRecord, w *RecordInput) { f.badPage = true }, ErrRecordEditRead},
		{"unscoped rows", func(f *editFake, r *DNSRecord, w *RecordInput) {
			f.rows = append(f.rows, DNSRecord{ID: "foreign", Type: "TXT", Name: "other.test"})
		}, ErrRecordEditRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, r, w := editFixture()
			tc.change(f, &r, &w)
			if _, err := verifyFake(f, r, w); !errors.Is(err, tc.want) || f.writes != 0 {
				t.Fatalf("error=%v writes=%d", err, f.writes)
			}
		})
	}
}

func TestReplaceVerifiedAmbiguousReadback(t *testing.T) {
	for _, tc := range []struct {
		name   string
		finish func(*editFake, DNSRecord, RecordInput) (string, error)
	}{
		{"old record still present", func(f *editFake, r DNSRecord, w RecordInput) (string, error) {
			f.rows = append(f.rows, resultRow(r, w))
			return "new-identity", nil
		}},
		{"changed proxy", func(f *editFake, r DNSRecord, w RecordInput) (string, error) {
			f.rows[0] = resultRow(r, w)
			f.rows[0].Proxied = true
			return "new-identity", nil
		}},
		{"lost sibling", func(f *editFake, r DNSRecord, w RecordInput) (string, error) {
			f.rows = []DNSRecord{resultRow(r, w)}
			return "", nil
		}},
		{"contradictory response ID", func(f *editFake, r DNSRecord, w RecordInput) (string, error) {
			f.rows[0] = resultRow(r, w)
			return "different-id", nil
		}},
		{"duplicate target", func(f *editFake, r DNSRecord, w RecordInput) (string, error) {
			f.rows[0] = resultRow(r, w)
			copy := f.rows[0]
			copy.ID = "duplicate"
			f.rows = append(f.rows, copy)
			return "", nil
		}},
		{"unchanged after timeout", func(f *editFake, r DNSRecord, w RecordInput) (string, error) { return "", context.DeadlineExceeded }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, r, w := editFixture()
			f.rows = append(f.rows, DNSRecord{ID: "sibling", Name: r.Name, Type: "TXT", TTL: 600, Content: "keep"})
			f.apply = tc.finish
			_, err := ReplaceVerified(context.Background(), f, tc.name, "example.test", r, w, func() bool { return true })
			if !errors.Is(err, ErrRecordEditUncertain) || f.writes != 1 || f.reads != 4 {
				t.Fatalf("error=%v writes=%d reads=%d", err, f.writes, f.reads)
			}
		})
	}
}

func TestReplaceVerifiedRevocation(t *testing.T) {
	f, r, w := editFixture()
	_, err := ReplaceVerified(context.Background(), f, "zone", "example.test", r, w, func() bool { return f.reads == 0 })
	if !errors.Is(err, ErrRecordEditDenied) || f.writes != 0 {
		t.Fatalf("error=%v writes=%d", err, f.writes)
	}
	f.apply = func(f *editFake, r DNSRecord, w RecordInput) (string, error) {
		f.rows[0] = resultRow(r, w)
		return f.rows[0].ID, nil
	}
	_, err = ReplaceVerified(context.Background(), f, "zone", "example.test", r, w, func() bool { return f.writes == 0 })
	if !errors.Is(err, ErrRecordEditUncertain) || f.writes != 1 || f.reads != 2 {
		t.Fatalf("error=%v writes=%d reads=%d", err, f.writes, f.reads)
	}
}

func TestReplaceVerifiedConcurrentEdit(t *testing.T) {
	f, r, w := editFixture()
	f.apply = func(f *editFake, r DNSRecord, w RecordInput) (string, error) {
		f.rows[0] = resultRow(r, w)
		return f.rows[0].ID, nil
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Go(func() { _, err := verifyFake(f, r, w); results <- err })
	}
	wg.Wait()
	close(results)
	done, conflict := 0, 0
	for err := range results {
		switch {
		case err == nil:
			done++
		case errors.Is(err, ErrRecordEditConflict):
			conflict++
		default:
			t.Fatal(err)
		}
	}
	if done != 1 || conflict != 1 || f.writes != 1 {
		t.Fatalf("success=%d conflicts=%d writes=%d", done, conflict, f.writes)
	}
}
