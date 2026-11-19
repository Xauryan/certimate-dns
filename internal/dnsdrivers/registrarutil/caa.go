package registrarutil

import (
	"fmt"
	"strconv"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

// FormatCAA encodes a provider value as a quoted DNS character string.
// RFC 1035 uses decimal octets, including for bytes outside printable ASCII.
func FormatCAA(flag int, tag, value string) string {
	var out strings.Builder
	out.WriteString(strconv.Itoa(flag))
	out.WriteByte(' ')
	out.WriteString(tag)
	out.WriteString(" \"")
	for i := 0; i < len(value); i++ {
		b := value[i]
		switch {
		case b == '"' || b == '\\':
			out.WriteByte('\\')
			out.WriteByte(b)
		case b < 32 || b > 126:
			fmt.Fprintf(&out, "\\%03d", b)
		default:
			out.WriteByte(b)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// ParseCAA accepts both the DNS editor's unquoted value and zone-file presentation.
func ParseCAA(content string) (flag int, tag, value string, err error) {
	content = strings.Trim(content, " \t")
	i := strings.IndexAny(content, " \t")
	if i < 1 {
		return 0, "", "", dns.ErrInvalidDNSRequest
	}
	n, err := strconv.ParseUint(content[:i], 10, 8)
	if err != nil {
		return 0, "", "", dns.ErrInvalidDNSRequest
	}
	remaining := strings.TrimLeft(content[i:], " \t")
	i = strings.IndexAny(remaining, " \t")
	if i < 1 || i > 255 {
		return 0, "", "", dns.ErrInvalidDNSRequest
	}
	tag = remaining[:i]
	for _, c := range tag {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return 0, "", "", dns.ErrInvalidDNSRequest
		}
	}
	raw := strings.TrimLeft(remaining[i:], " \t")
	if raw == "" || strings.ContainsAny(raw, "\r\n") {
		return 0, "", "", dns.ErrInvalidDNSRequest
	}
	quoted := raw[0] == '"'
	if quoted {
		if len(raw) < 2 || raw[len(raw)-1] != '"' {
			return 0, "", "", dns.ErrInvalidDNSRequest
		}
		raw = raw[1 : len(raw)-1]
	}
	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			return 0, "", "", dns.ErrInvalidDNSRequest
		case '\\':
			i++
			if i == len(raw) {
				return 0, "", "", dns.ErrInvalidDNSRequest
			}
			if raw[i] >= '0' && raw[i] <= '9' {
				if len(raw)-i < 3 {
					return 0, "", "", dns.ErrInvalidDNSRequest
				}
				n, err := strconv.ParseUint(raw[i:i+3], 10, 8)
				if err != nil {
					return 0, "", "", dns.ErrInvalidDNSRequest
				}
				out.WriteByte(byte(n))
				i += 2
			} else {
				out.WriteByte(raw[i])
			}
		default:
			out.WriteByte(raw[i])
		}
	}
	return int(n), tag, out.String(), nil
}
