package dnsautomation

import "context"

// Control applies the same optimistic concurrency and execution checks used by
// the administration API. Callers authorize the current task and its version.
func (s *Service) Control(ctx context.Context, id, actor, action string, version int) error {
	return s.control(ctx, id, actor, action, version)
}

// PublicError returns a bounded message suitable for an external interface.
func PublicError(err error) (int, string) { return publicError(err) }
