package dnsbatch

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	bind "github.com/miekg/dns"
)

func importZone(text, origin string) ([]Change, error) {
	if !validName(origin) || text == "" || len(text) > 1<<20 {
		return nil, errors.New("invalid zone file or origin (maximum 1 MiB)")
	}
	for _, line := range strings.Split(text, "\n") {
		s := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(s, "$") && !(strings.HasPrefix(s, "$ORIGIN ") || strings.HasPrefix(s, "$ORIGIN\t") || strings.HasPrefix(s, "$TTL ") || strings.HasPrefix(s, "$TTL\t")) {
			return nil, errors.New("only $ORIGIN and $TTL directives are supported")
		}
	}
	zp := bind.NewZoneParser(strings.NewReader(text), bind.Fqdn(origin), "")
	zp.SetIncludeAllowed(false)
	result := []Change{}
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		if h.Class != bind.ClassINET || !withinZone(h.Name, origin) {
			return nil, errors.New("only IN records in the selected zone can be imported")
		}
		comment := strings.ToUpper(zp.Comment())
		if strings.Contains(comment, "CF_TAGS=") || strings.Contains(comment, "CF-PROXIED:") || strings.Contains(comment, "CF-FLATTEN-CNAME:") {
			return nil, errors.New("Cloudflare zone directives require a native importer")
		}
		c, err := importedRecord(rr)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", len(result)+1, err)
		}
		result = append(result, c)
		if len(result) > maxChanges {
			return nil, errors.New("zone file exceeds 200 records per preview")
		}
	}
	if zp.Err() != nil {
		return nil, errors.New("invalid BIND zone file")
	}
	if len(result) == 0 {
		return nil, errors.New("empty zone file")
	}
	return result, nil
}

func targetName(s string) string {
	if s == "." {
		return s
	} // Null MX and unavailable SRV targets use the root.
	return canonicalName(s)
}

func importedRecord(rr bind.RR) (Change, error) {
	h := rr.Header()
	c := Change{Action: "create", Name: canonicalName(h.Name), Type: bind.TypeToString[h.Rrtype], TTL: int(h.Ttl)}
	var err error
	switch r := rr.(type) {
	case *bind.A:
		c.Content = r.A.String()
	case *bind.AAAA:
		c.Content = r.AAAA.String()
	case *bind.CNAME:
		c.Content = targetName(r.Target)
	case *bind.DNAME:
		c.Content = targetName(r.Target)
	case *bind.NS:
		c.Content = targetName(r.Ns)
	case *bind.PTR:
		c.Content = targetName(r.Ptr)
	case *bind.MX:
		p := int(r.Preference)
		c.Priority = &p
		c.Content = targetName(r.Mx)
	case *bind.SRV:
		c.Content = fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, targetName(r.Target))
	case *bind.URI:
		p := int(r.Priority)
		c.Priority = &p
		// The provider takes priority separately and expects weight and target as RDATA.
		_, c.Content, _ = strings.Cut(rawRdata(rr), " ")
	case *bind.CAA:
		c.Content = rawRdata(rr)
	case *bind.TXT:
		c.Content, err = plainString(r.Txt)
	case *bind.SPF:
		c.Content, err = plainString(r.Txt)
	default:
		return Change{}, fmt.Errorf("cannot import DNS type %q", c.Type)
	}
	if err != nil {
		return Change{}, err
	}
	if err := validateData(c); err != nil {
		return Change{}, err
	}
	return c, nil
}

func rawRdata(rr bind.RR) string { return strings.TrimPrefix(rr.String(), rr.Header().String()) }

// TXT/SPF hold one raw UTF-8 value in the provider model. Preserve escapes as
// octets. Multiple character strings have significant wire boundaries.
func plainString(parts []string) (string, error) {
	if len(parts) != 1 {
		return "", errors.New("multiple character strings require native import")
	}
	p := parts[0]
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '\\' {
			b.WriteByte(p[i])
			continue
		}
		i++
		if i == len(p) {
			return "", errors.New("incomplete zone string escape")
		}
		if i+3 <= len(p) && digits(p[i:i+3]) {
			value, err := strconv.ParseUint(p[i:i+3], 10, 8)
			if err != nil {
				return "", errors.New("invalid zone string octet")
			}
			b.WriteByte(byte(value))
			i += 2
		} else {
			b.WriteByte(p[i])
		}
	}
	s := b.String()
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return "", errors.New("binary character strings require native import")
	}
	return s, nil
}

func digits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func quotedString(s string) (string, error) {
	if len(s) > 255 || !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return "", errors.New("value cannot be encoded as one DNS character string; use versioned JSON export")
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 32 || c >= 127:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

func exportZone(rows []dns.DNSRecord, origin string, provider ...string) (string, error) {
	var body strings.Builder
	for i, r := range rows {
		if !withinZone(r.Name, origin) || r.TTL <= 0 || int64(r.TTL) > math.MaxUint32 {
			return "", fmt.Errorf("record %d: invalid owner or TTL", i+1)
		}
		driver := ""
		if len(provider) > 0 {
			driver = provider[0]
		}
		value, err := exportValue(r, driver)
		if err != nil {
			return "", fmt.Errorf("record %d: %w", i+1, err)
		}
		fmt.Fprintf(&body, "%s\t%d\tIN\t%s\t%s\n", bind.Fqdn(r.Name), r.TTL, r.Type, value)
	}
	return body.String(), nil
}

var errMetadata = errors.New("BIND cannot preserve the provider metadata of this record; use versioned JSON export")

func exportValue(r dns.DNSRecord, provider string) (string, error) {
	line := strings.ToLower(r.Line)
	dnsOnly := (provider == "cloudflare" || provider == "aliyunesa") && line == "0"
	switch strings.ToLower(r.Status) {
	case "", "enable", "enabled", "active":
	default:
		return "", errMetadata
	}
	if r.ReadOnly || r.Description != "" || r.Proxied || (line != "" && line != "default" && line != "默认" && !dnsOnly) {
		return "", errMetadata
	}
	if r.Weight != nil && !(r.Type == "SRV" && (provider == "aliyunesa" || provider == "jdcloud")) {
		return "", errMetadata
	}
	if r.Priority != nil && r.Type != "MX" && r.Type != "SRV" && r.Type != "URI" {
		return "", errMetadata
	}
	c := Change{Type: r.Type, Content: r.Content, Priority: r.Priority}
	if err := validateData(c); err != nil {
		return "", err
	}
	switch r.Type {
	case "TXT", "SPF":
		return quotedString(r.Content)
	case "A", "AAAA":
		return r.Content, nil
	case "CNAME", "NS", "PTR", "DNAME":
		return bind.Fqdn(r.Content), nil
	case "MX":
		parts := strings.Fields(r.Content)
		if len(parts) == 2 {
			return parts[0] + " " + bind.Fqdn(parts[1]), nil
		}
		if r.Priority == nil || *r.Priority < 0 || *r.Priority > 65535 {
			return "", errors.New("missing or invalid MX priority; use versioned JSON export")
		}
		return strconv.Itoa(*r.Priority) + " " + bind.Fqdn(parts[0]), nil
	case "SRV", "URI", "CAA":
		if r.Type == "URI" && r.Priority == nil {
			return "", errors.New("missing URI priority; use versioned JSON export")
		}
		rr, err := structuredRR(r.Type, r.Content, r.Priority)
		if err != nil {
			return "", err
		}
		if srv, ok := rr.(*bind.SRV); ok {
			if r.Priority != nil && int(srv.Priority) != *r.Priority || r.Weight != nil && int(srv.Weight) != *r.Weight {
				return "", errMetadata
			}
		}
		return rawRdata(rr), nil
	default:
		return "", fmt.Errorf("BIND cannot encode provider type %q; use versioned JSON export", r.Type)
	}
}
