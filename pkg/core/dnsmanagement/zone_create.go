package dnsmanagement

import "context"

// ZoneCreator is implemented by DNS accounts that can provision a remote zone.
type ZoneCreator interface {
	CreateZone(context.Context, string) (*Zone, error)
}
