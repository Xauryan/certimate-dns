package dnsbatch

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pocketbase/dbx"
)

type scope struct{ provider, access, zone, actor string }

func (s scope) filter() dbx.HashExp {
	return dbx.HashExp{"provider": s.provider, "access": s.access, "zone": s.zone}
}

type Plan struct {
	ID       string `json:"id"`
	Actor    string `json:"actor"`
	Created  int64  `json:"created"`
	State    string `json:"state"`
	Items    []Item `json:"items"`
	revision int
	digest   string
}

var errConflict = errors.New("preview is stale or already claimed; inspect its history")
var errMissing = errors.New("batch plan not found")

func saveNew(db dbx.Builder, s scope, changes []Change, items []Item) (*Plan, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	plan := &Plan{ID: hex.EncodeToString(nonce[:]), Actor: s.actor, Created: time.Now().Unix(), State: "preview", Items: items, digest: digest(changes)}
	payload, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	_, err = db.Insert("dns_batch_plans", dbx.Params{
		"id": plan.ID, "provider": s.provider, "access": s.access, "zone": s.zone, "actor": s.actor,
		"created": plan.Created, "state": plan.State, "digest": plan.digest, "items": string(payload),
	}).Execute()
	return plan, err
}

func loadPlan(db dbx.Builder, s scope, id string) (*Plan, error) {
	where := s.filter()
	where["id"] = id
	var p Plan
	var raw string
	err := db.Select("id", "actor", "created", "state", "revision", "digest", "items").From("dns_batch_plans").Where(where).
		Row(&p.ID, &p.Actor, &p.Created, &p.State, &p.revision, &p.digest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errMissing
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(raw), &p.Items); err != nil {
		return nil, err
	}
	return &p, nil
}

// Compare-and-swap persists the dispatch intent before every outbound call.
// Losing a race cannot authorize another provider write.
func (p *Plan) save(db dbx.Builder) error {
	raw, err := json.Marshal(p.Items)
	if err != nil {
		return err
	}
	res, err := db.Update("dns_batch_plans", dbx.Params{"state": p.State, "items": string(raw), "revision": p.revision + 1},
		dbx.HashExp{"id": p.ID, "revision": p.revision}).Execute()
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errConflict
	}
	p.revision++
	return nil
}
func (p Plan) public() Plan {
	items := make([]Item, len(p.Items))
	for i, r := range p.Items {
		items[i] = Item{Action: r.Action, ID: r.ID, State: r.State}
	}
	p.Items = items
	return p
}

type Summary struct {
	ID      string `json:"id" db:"id"`
	Actor   string `json:"actor" db:"actor"`
	Created int64  `json:"created" db:"created"`
	State   string `json:"state" db:"state"`
}

func history(db dbx.Builder, s scope, page int) (map[string]any, error) {
	var n int
	if err := db.Select("COUNT(*)").From("dns_batch_plans").Where(s.filter()).Row(&n); err != nil {
		return nil, err
	}
	list := []Summary{}
	err := db.Select("id", "actor", "created", "state").From("dns_batch_plans").Where(s.filter()).OrderBy("created DESC", "id").Limit(20).Offset(int64(page-1) * 20).All(&list)
	return map[string]any{"items": list, "total": n}, err
}
