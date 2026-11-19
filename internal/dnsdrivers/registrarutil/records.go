// Package registrarutil shares provider wire and inventory checks.
package registrarutil

import (
	"errors"
	"strconv"
	"strings"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

var ErrInventory = errors.New("incomplete or changing DNS provider inventory")

// CompletePage verifies that the reported total accounts for every row on this page.
func CompletePage(total, offset, limit, count int) bool {
	return total >= 0 && offset >= 0 && limit > 0 && count == min(limit, max(0, total-offset))
}

// Walk checks every page before the caller acts on a record found in the inventory.
// The vendor API must return distinct IDs and a stable total across the traversal.
func Walk[T any](limit int, fetch func(page int) ([]T, int, error), id func(T) string, visit func(T) error) error {
	seen := make(map[string]bool)
	total := -1
	for page := 1; ; page++ {
		rows, n, err := fetch(page)
		if err != nil {
			return err
		}
		if (total >= 0 && total != n) || !CompletePage(n, (page-1)*limit, limit, len(rows)) {
			return ErrInventory
		}
		total = n
		for _, r := range rows {
			key := id(r)
			if key == "" || seen[key] {
				return ErrInventory
			}
			seen[key] = true
			if err := visit(r); err != nil {
				return err
			}
		}
		if len(seen) == total {
			return nil
		}
	}
}

// ParseMX, ParseSRV and ParseCAA decode the presentation used by the DNS record editor.
func ParseMX(content string) (priority int, exchange string, err error) {
	parts := strings.Fields(content)
	if len(parts) != 2 {
		return 0, "", dns.ErrInvalidDNSRequest
	}
	value, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, "", dns.ErrInvalidDNSRequest
	}
	return int(value), parts[1], nil
}

func ParseSRV(content string) (priority, weight, port int, target string, err error) {
	parts := strings.Fields(content)
	if len(parts) != 4 {
		return 0, 0, 0, "", dns.ErrInvalidDNSRequest
	}
	values := [3]int{}
	for i := range values {
		v, err := strconv.ParseUint(parts[i], 10, 16)
		if err != nil {
			return 0, 0, 0, "", dns.ErrInvalidDNSRequest
		}
		values[i] = int(v)
	}
	return values[0], values[1], values[2], parts[3], nil
}
