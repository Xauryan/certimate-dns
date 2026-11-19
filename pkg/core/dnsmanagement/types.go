package dnsmanagement

import (
	"context"
	"errors"
)

const DNSPageSize = 20

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Line    string `json:"line,omitempty"`
	Status  string `json:"status,omitempty"`
	Proxied bool   `json:"proxied"`
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
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
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
