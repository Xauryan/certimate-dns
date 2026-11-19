package dnsbatch

import (
	"context"
	"errors"
	"time"

	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	"github.com/pocketbase/dbx"
)

func dispatch(ctx context.Context, p dns.Provider, s scope, c Change) (string, error) {
	zone := s.zone
	switch c.Action {
	case "create":
		caps, _ := dns.ProviderCapabilities(s.provider)
		return p.CreateDNSRecord(ctx, zone, createInput(c, caps))
	case "patch":
		return p.PatchDNSRecord(ctx, zone, c.ID, dns.RecordPatch{Content: c.Content, TTL: c.TTL})
	case "delete":
		return p.DeleteDNSRecord(ctx, zone, c.ID)
	case "group":
		g, ok := p.(Groups)
		if !ok {
			return "", errors.New("unsupported provider groups")
		}
		return c.ID, g.SetBatchGroup(ctx, zone, c.ID, c.Value)
	default:
		m, ok := p.(Metadata)
		if !ok {
			return "", errors.New("unsupported provider attribute")
		}
		return c.ID, m.SetBatchAttribute(ctx, zone, c.ID, c.Action, c.Value)
	}
}
func (p *Plan) summarize() {
	p.State = "completed"
	for _, it := range p.Items {
		switch it.State {
		case "sending", "unknown":
			p.State = "uncertain"
			return
		case "applied", "observed":
		default:
			p.State = "partial"
		}
	}
}
func (p *Plan) stopPending() {
	for i := range p.Items {
		if p.Items[i].State == "ready" {
			p.Items[i].State = "not_sent"
		}
	}
}

// apply intentionally never resumes a claimed plan. A new preview requires
// fresh provider reads and separate confirmation, including after a restart.
func (p *Plan) apply(ctx context.Context, db dbx.Builder, client dns.Provider, s scope, origin string, changes []Change, authorize func() error) error {
	if p.State != "preview" || p.Actor != s.actor || p.digest != digest(changes) || len(p.Items) != len(changes) || time.Since(time.Unix(p.Created, 0)) > 30*time.Minute {
		return errConflict
	}
	p.State = "applying"
	if err := p.save(db); err != nil {
		return err
	}
	for i, c := range changes {
		item := &p.Items[i]
		if err := authorize(); err != nil {
			p.stopPending()
			p.summarize()
			if saveErr := p.save(db); saveErr != nil {
				return saveErr
			}
			return err
		}
		rows, err := zoneRecords(ctx, client, s.zone, origin)
		if err != nil {
			p.stopPending()
			break
		}
		fresh, _, err := prepare(ctx, client, s.provider, s.zone, origin, rows, []Change{c})
		if err != nil || fresh[0].Before != item.Before {
			item.State = "conflict"
			continue
		}
		if ctx.Err() != nil {
			p.stopPending()
			break
		}
		if err := authorize(); err != nil {
			p.stopPending()
			p.summarize()
			if saveErr := p.save(db); saveErr != nil {
				return saveErr
			}
			return err
		}
		item.State = "sending"
		if err := p.save(db); err != nil {
			return err
		}
		id, err := dispatch(ctx, client, s, c)
		if err != nil || id == "" || (c.Action != "create" && c.Action != "patch" && id != c.ID) {
			item.State = "unknown"
			p.stopPending()
			break
		}
		item.ID = id
		if c.Action == "create" && (len(item.Expected) > 0 || item.MatchLine || item.MatchPriority) {
			// Preserve the new ID before a dependent write or verification read.
			if err := p.save(db); err != nil {
				return err
			}
			if err := item.finishCreate(ctx, client, s, origin, c, authorize); err != nil {
				item.State = "unknown"
				p.stopPending()
				break
			}
		}
		item.State = "applied"
		if err := p.save(db); err != nil {
			return err
		}
	}
	p.summarize()
	return p.save(db)
}

func (p *Plan) reconcile(ctx context.Context, db dbx.Builder, client dns.Provider, s scope, origin string) error {
	if p.State != "uncertain" && p.State != "applying" {
		return errConflict
	}
	rows, err := zoneRecords(ctx, client, s.zone, origin)
	if err != nil {
		return err
	}
	for i := range p.Items {
		item := &p.Items[i]
		if item.State != "unknown" && item.State != "sending" {
			continue
		}
		old := byID(rows, item.ID)
		matched := false
		switch item.Action {
		case "delete":
			matched = old == nil
		case "patch":
			matched = old != nil && desiredKey(matchingData(*old, s.provider, false, item.MatchPriority)) == item.After
		case "create":
			id, err := item.verifyCreate(ctx, client, s, origin, rows)
			if err != nil {
				return err
			}
			matched = id != ""
			if matched {
				item.ID = id
			}
		default:
			if old != nil {
				v, err := readAttribute(ctx, client, s.zone, item.ID, item.Action)
				if err != nil {
					return err
				}
				matched = digest(v) == item.After
			}
		}
		if matched {
			item.State = "observed"
		} else {
			item.State = "unknown"
		}
	}
	p.stopPending()
	p.summarize()
	return p.save(db)
}

func (item *Item) finishCreate(ctx context.Context, p dns.Provider, s scope, origin string, c Change, authorize func() error) error {
	caps, _ := dns.ProviderCapabilities(s.provider)
	for _, a := range createAttributes(caps, c) {
		if err := authorize(); err != nil {
			return err
		}
		rows, err := zoneRecords(ctx, p, s.zone, origin)
		if err != nil {
			return err
		}
		r := byID(rows, item.ID)
		if r == nil || r.ReadOnly || desiredKey(matchingData(logicalRecord(*r, s.provider, origin), s.provider, item.MatchLine, item.MatchPriority)) != item.After {
			return errConflict
		}
		if err := authorize(); err != nil {
			return err
		}
		a.ID = item.ID
		if _, err := dispatch(ctx, p, s, a); err != nil {
			return err
		}
	}
	if err := authorize(); err != nil {
		return err
	}
	rows, err := zoneRecords(ctx, p, s.zone, origin)
	if err != nil {
		return err
	}
	observed, err := item.verifyCreate(ctx, p, s, origin, rows)
	if err != nil {
		return err
	}
	if observed != item.ID {
		return errConflict
	}
	return nil
}
