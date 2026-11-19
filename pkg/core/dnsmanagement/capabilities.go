package dnsmanagement

import "slices"

// Capabilities describes inputs that a management driver can send on record creation.
// A provider plan or zone can impose a higher minimum TTL.
type Capabilities struct {
	Types         []string `json:"types"`
	MinTTL        int      `json:"minTTL"`
	MaxTTL        int      `json:"maxTTL"`
	DefaultTTL    int      `json:"defaultTTL"`
	SpecialTTLs   []int    `json:"specialTTLs,omitempty"`
	PriorityTypes []string `json:"priorityTypes,omitempty"`
	ZoneCreate    bool     `json:"zoneCreate"`
	Export        bool     `json:"export"`
	Line          bool     `json:"line"`
	Weight        bool     `json:"weight"`
	Description   bool     `json:"description"`
}

func (c Capabilities) AllowsType(recordType string) bool { return slices.Contains(c.Types, recordType) }
func (c Capabilities) AllowsTTL(ttl int) bool {
	return ttl >= c.MinTTL && ttl <= c.MaxTTL || slices.Contains(c.SpecialTTLs, ttl)
}
