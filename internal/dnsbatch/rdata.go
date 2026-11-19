package dnsbatch

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	bind "github.com/miekg/dns"
)

// validateData checks the record's provider-facing content. MX and URI use
// separate priority fields on creation. Some provider listings return the full
// RDATA for MX, so both representations can be read.
func validateData(c Change) error {
	if c.Content == "" || len(c.Content) > 65535 || strings.ContainsRune(c.Content, 0) {
		return errors.New("invalid or missing record content")
	}
	if c.Type != "TXT" && c.Type != "SPF" && strings.IndexFunc(c.Content, unicode.IsControl) >= 0 {
		return errors.New("record content contains a control character")
	}
	switch c.Type {
	case "A", "AAAA":
		a, err := netip.ParseAddr(c.Content)
		if err != nil || a.Zone() != "" || (c.Type == "A") != a.Is4() {
			return errors.New("invalid IP address for record type")
		}
	case "CNAME", "NS", "PTR", "DNAME", "ALIAS", "ANAME":
		if !validName(c.Content) {
			return errors.New("invalid domain target")
		}
	case "MX":
		f := strings.Fields(c.Content)
		if len(f) == 1 && validName(f[0]) {
			return nil
		}
		if len(f) != 2 || !validName(f[1]) {
			return errors.New("invalid MX target or preference")
		}
		n, err := strconv.ParseUint(f[0], 10, 16)
		if err != nil || c.Priority != nil && *c.Priority != int(n) {
			return errors.New("invalid or conflicting MX preference")
		}
	case "SRV", "CAA", "URI":
		_, err := structuredRR(c.Type, c.Content, c.Priority)
		return err
	case "REDIRECT_URL", "FORWARD_URL", "EXPLICIT_URL", "IMPLICIT_URL":
		u, err := url.ParseRequestURI(c.Content)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("invalid redirect URL")
		}
	case "APP":
		// Technitium uses appName, classPath, and optional application data.
		fields := strings.SplitN(c.Content, " ", 3)
		if len(fields) < 2 || fields[0] == "" || fields[1] == "" {
			return errors.New("APP requires an application and class name")
		}
	case "TXT", "SPF":
	default:
		return errors.New("unsupported record type")
	}
	return nil
}

func structuredRR(kind, content string, priority *int) (bind.RR, error) {
	if kind == "URI" {
		n := 0
		if priority != nil {
			n = *priority
		}
		if n < 0 || n > 65535 {
			return nil, errors.New("invalid URI priority")
		}
		content = strconv.Itoa(n) + " " + content
	}
	// The input is one record value, with an explicitly fixed owner and class.
	// Parentheses and comment syntax outside quoted strings would discard or
	// reinterpret input. Escapes are interpreted by the zone parser.
	quoted, escaped := false, false
	for _, ch := range content {
		if unicode.IsControl(ch) {
			return nil, errors.New("invalid structured record content")
		}
		if escaped {
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			escaped = true
		case '"':
			quoted = !quoted
		case ';', '(', ')':
			if !quoted {
				return nil, errors.New("quote literal record data")
			}
		}
	}
	if quoted || escaped {
		return nil, errors.New("unterminated record value")
	}
	rr, err := bind.NewRR(". 60 IN " + kind + " " + content)
	if err != nil || rr == nil {
		return nil, errors.New("invalid " + kind + " record data")
	}
	switch r := rr.(type) {
	case *bind.SRV:
		if !validName(r.Target) {
			return nil, errors.New("invalid SRV target")
		}
	case *bind.CAA:
		if len(r.Tag) == 0 || len(r.Tag) > 255 {
			return nil, errors.New("invalid CAA property tag")
		}
		for _, ch := range r.Tag {
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') {
				return nil, errors.New("invalid CAA property tag")
			}
		}
	case *bind.URI:
		if r.Target == "" {
			return nil, errors.New("URI target is empty")
		}
	}
	return rr, nil
}

// canonicalContent compares the wire value projected by each provider. MX
// preference may be embedded in content or reported in its own field.
func canonicalContent(c Change) string {
	switch c.Type {
	case "A", "AAAA":
		if a, err := netip.ParseAddr(c.Content); err == nil {
			return a.String()
		}
	case "MX":
		f := strings.Fields(c.Content)
		if len(f) == 1 {
			exchange := targetName(f[0])
			if c.Priority != nil {
				return strconv.Itoa(*c.Priority) + " " + exchange
			}
			return exchange
		}
		if len(f) == 2 {
			if n, err := strconv.ParseUint(f[0], 10, 16); err == nil && (c.Priority == nil || *c.Priority == int(n)) {
				return strconv.FormatUint(n, 10) + " " + targetName(f[1])
			}
		}
	case "CNAME", "NS", "PTR", "ALIAS", "DNAME", "ANAME":
		return targetName(c.Content)
	case "CAA", "SRV", "URI":
		rr, err := structuredRR(c.Type, c.Content, nil)
		if err == nil {
			switch r := rr.(type) {
			case *bind.SRV:
				r.Target = strings.ToLower(r.Target)
			case *bind.URI:
				// Weight and target are content; priority is a separate attribute.
				_, value, _ := strings.Cut(rawRdata(rr), " ")
				return value
			}
			return rawRdata(rr)
		}
	}
	return c.Content
}
