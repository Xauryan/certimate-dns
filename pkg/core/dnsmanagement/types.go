package dnsmanagement

import (
	"context"
	"errors"
	"slices"
)

const DNSPageSize = 20

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type DNSRecord struct {
	UpdatedAt   string `json:"updatedAt,omitempty"`
	ID          string `json:"id"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Content     string `json:"content"`
	TTL         int    `json:"ttl"`
	Line        string `json:"line,omitempty"`
	Status      string `json:"status,omitempty"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
	Description string `json:"description,omitempty"`
	Weight      *int   `json:"weight,omitempty"`
	Priority    *int   `json:"priority,omitempty"`
	Proxied     bool   `json:"proxied"`
}

type PageInfo struct {
	Page  int `json:"page"`
	Total int `json:"total_count"`
}

type DNSPage[T any] struct {
	Items []T      `json:"result"`
	Info  PageInfo `json:"result_info"`
}

type RecordInput struct {
	Priority    *int   `json:"priority,omitempty"`
	Weight      *int   `json:"weight,omitempty"`
	Description string `json:"description,omitempty"`
	Line        string `json:"line,omitempty"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Content     string `json:"content"`
	TTL         int    `json:"ttl"`
}

// RecordPatch changes only the value and TTL. Proxy settings, tags and comments stay with the record.
type RecordPatch struct {
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

var ErrInvalidDNSRequest = errors.New("invalid DNS request")

type Provider interface {
	Zones(context.Context, int) (*DNSPage[Zone], error)
	DNSRecords(context.Context, string, int, string) (*DNSPage[DNSRecord], error)
	CreateDNSRecord(context.Context, string, RecordInput) (string, error)
	PatchDNSRecord(context.Context, string, string, RecordPatch) (string, error)
	DeleteDNSRecord(context.Context, string, string) (string, error)
}

// SupportedProviders lists account types with a registered management adapter.
func SupportedProviders() []string {
	return []string{"aliyun", "aliyunesa", "aws", "baiducloud", "bt", "cloudflare", "dnsla", "dnsmgr", "dynv6", "goedge", "henet", "huaweicloud", "jdcloud", "namesilo", "powerdns", "qingcloud", "spaceship", "technitiumdns", "tencentcloud", "tencenteo", "volcengine", "westcn"}
}
func IsSupportedProvider(id string) bool { return slices.Contains(SupportedProviders(), id) }
