package dnsmanagement

import (
	"context"
	"strings"
)

// RecordEditCapabilities describes identity changes that the provider can make
// without an intermediate delete/create. A given record may have additional
// restrictions (for example, a managed record or a multi-value record set).
type RecordEditCapabilities struct {
	Rename   bool `json:"rename"`
	Retype   bool `json:"retype"`
	Priority bool `json:"priority"`
	// PresentationTXT identifies providers that expose TXT in DNS presentation format.
	PresentationTXT bool `json:"presentationTXT,omitempty"`
}

var quoteTXT = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// QuoteRecordTXT formats a plain TXT value for a DNS presentation API.
func QuoteRecordTXT(value string) string {
	if strings.HasPrefix(value, `"`) {
		return value
	}
	return `"` + quoteTXT.Replace(value) + `"`
}

// RecordEditor replaces fields on an existing record while preserving provider
// metadata such as comments, proxy state, routing policy, groups and status.
// prior is the version observed in the authorized zone. desired includes the
// complete intended name, type, content, TTL and applicable priority. Its
// line, description and weight describe the state to preserve. Callers manage
// changes to those attributes separately. The returned ID may differ from prior.ID.
type RecordEditor interface {
	RecordEditCapabilities() RecordEditCapabilities
	ReplaceDNSRecord(ctx context.Context, zone string, prior DNSRecord, desired RecordInput) (string, error)
}

// ZoneRecordEditor reports capabilities of the specific backing provider for
// adapters that proxy more than one kind of authoritative DNS service.
type ZoneRecordEditor interface {
	RecordEditor
	ZoneRecordEditCapabilities(ctx context.Context, zone string) (RecordEditCapabilities, error)
}

func RecordEditCapabilitiesForZone(ctx context.Context, p Provider, zone string) (RecordEditCapabilities, error) {
	if editor, ok := p.(ZoneRecordEditor); ok {
		return editor.ZoneRecordEditCapabilities(ctx, zone)
	}
	if editor, ok := p.(RecordEditor); ok {
		return editor.RecordEditCapabilities(), nil
	}
	return RecordEditCapabilities{}, nil
}
