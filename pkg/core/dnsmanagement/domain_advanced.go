package dnsmanagement

type RecordLine struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Parent string `json:"parent,omitempty"`
}

// ZoneDetails contains only DNS configuration that can be shown to zone readers.
type ZoneDetails struct {
	Name        string                  `json:"name"`
	Status      string                  `json:"status,omitempty"`
	Plan        string                  `json:"plan,omitempty"`
	MinTTL      int                     `json:"minTTL,omitempty"`
	Lines       []RecordLine            `json:"lines"`
	Nameservers []string                `json:"nameservers,omitempty"`
	RecordEdit  *RecordEditCapabilities `json:"recordEdit,omitempty"`
}

type DomainAlias struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type WeightRule struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Line    string `json:"line"`
	Enabled bool   `json:"enabled"`
}

type RecordGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type RecordLog struct {
	Time   string `json:"time"`
	Action string `json:"action"`
}
