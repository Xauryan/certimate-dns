package dnsmigrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// Promotion is an administrator's explicit choice, supplied in the local
// bindings file after matching the exported inventory to native resources.
type Promotion struct {
	Kind              string   `json:"kind"`
	LegacyID          int64    `json:"legacyId"`
	TargetID          string   `json:"targetId"`
	AdditionalTargets []string `json:"additionalTargets,omitempty"`
	Role              string   `json:"role,omitempty"`
	Confirm           bool     `json:"confirm"`
}

type PromotionResult struct {
	Promotion
	Action       string `json:"action"`
	Reason       string `json:"reason,omitempty"`
	sourceDigest string
	work         promotionWork
}

type promotionWork struct {
	Conflict string
	Apply    func(context.Context, core.App) error
}

type sourceKey struct {
	kind string
	id   int64
}

func exclusiveTarget(kind string) bool {
	switch kind {
	case "user", "cert_account", "cert_order", "cert_deploy", "cert_cname", "optimizeip", "sctask", "dmtask":
		return true
	}
	return false
}

func (b Bindings) validatePromotions() error {
	seen := map[sourceKey]bool{}
	targets := map[[2]string]bool{}
	for idx, v := range b.Promotions {
		key := sourceKey{v.Kind, v.LegacyID}
		if !v.Confirm || v.LegacyID <= 0 || seen[key] || !identifier.MatchString(v.TargetID) {
			return fmt.Errorf("promotion %d requires unique source identity, target ID and explicit confirmation", idx+1)
		}
		seen[key] = true
		switch v.Kind {
		case "user", "permission", "domain_alias", "cert_account", "cert_order", "cert_domain", "cert_deploy", "cert_cname", "optimizeip", "sctask", "dmtask":
		default:
			return fmt.Errorf("unknown promotion kind in entry %d", idx+1)
		}
		if v.Kind != "permission" && !(v.Kind == "cert_order" && v.Role == "certificate") && v.Role != "" {
			return fmt.Errorf("unexpected role in promotion %d", idx+1)
		}
		if len(v.AdditionalTargets) > 0 && v.Kind != "optimizeip" || len(v.AdditionalTargets) > 64 {
			return fmt.Errorf("unexpected additional targets in promotion %d", idx+1)
		}
		for _, id := range append([]string{v.TargetID}, v.AdditionalTargets...) {
			target := [2]string{v.Kind, id}
			if !identifier.MatchString(id) || (exclusiveTarget(v.Kind) && targets[target]) {
				return fmt.Errorf("invalid or duplicate target in promotion %d", idx+1)
			}
			targets[target] = true
		}
	}
	return nil
}

func (p *planner) sourceItem(kind string, id int64) (Item, bool) {
	if p.itemsByKey == nil {
		p.itemsByKey = make(map[sourceKey]Item, len(p.report.Items))
		for _, i := range p.report.Items {
			p.itemsByKey[sourceKey{i.Kind, i.Legacy}] = i
		}
	}
	i, ok := p.itemsByKey[sourceKey{kind, id}]
	return i, ok
}

func (p *planner) promotionTarget(kind string, id int64) (string, bool) {
	if p.selected == nil {
		p.selected = make(map[sourceKey]string, len(p.bindings.Promotions))
		for _, v := range p.bindings.Promotions {
			p.selected[sourceKey{v.Kind, v.LegacyID}] = v.TargetID
		}
	}
	target, ok := p.selected[sourceKey{kind, id}]
	return target, ok
}

func (p *planner) planPromotion(b Promotion) (PromotionResult, error) {
	// Preserve the caller's input while keeping saved bindings canonical across replays.
	b.AdditionalTargets = slices.Clone(b.AdditionalTargets)
	slices.Sort(b.AdditionalTargets)
	r := PromotionResult{Promotion: b, Action: "conflict"}
	source, ok := p.sourceItem(b.Kind, b.LegacyID)
	if !ok || source.Action == "conflict" {
		r.Reason = "source identity is missing or conflicted"
		return r, nil
	}
	if source.Action != "stage" && source.Action != "refreshStage" && !(source.Action == "unchanged" && source.Reason == "stage") && b.TargetID != source.Target {
		r.Reason = "source is already mapped to a different native resource"
		return r, nil
	}
	r.sourceDigest = source.digest
	var saved struct {
		Binding      string `db:"binding"`
		SourceDigest string `db:"source_digest"`
	}
	err := p.db.NewQuery("SELECT binding,source_digest FROM dns_import_promotions WHERE source={:s} AND kind={:k} AND legacy_id={:id}").Bind(dbx.Params{"s": p.manifest.Source, "k": b.Kind, "id": b.LegacyID}).WithContext(p.ctx).One(&saved)
	previous := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	encoded, err := json.Marshal(b)
	if err != nil {
		return r, err
	}
	if previous && (saved.Binding != string(encoded) || saved.SourceDigest != source.digest) {
		r.Reason = "confirmed mapping or source identity changed since promotion"
		return r, nil
	}
	// Check against approvals from earlier imports, even when only a subset is
	// selected for this run. Secondary optimization rows are exclusive too.
	if exclusiveTarget(b.Kind) {
		for _, id := range append([]string{b.TargetID}, b.AdditionalTargets...) {
			_, used, err := p.scalar(`SELECT 1 FROM dns_import_promotions WHERE source={:s} AND kind={:k} AND legacy_id<>{:legacy}
				AND (target_id={:id} OR EXISTS(SELECT 1 FROM json_each(binding,'$.additionalTargets') WHERE value={:id})) LIMIT 1`, dbx.Params{"s": p.manifest.Source, "k": b.Kind, "legacy": b.LegacyID, "id": id})
			if err != nil {
				return r, err
			}
			if used {
				r.Reason = "target already confirmed for another source object"
				return r, nil
			}
		}
	}
	switch b.Kind {
	case "user", "permission":
		r.work, err = p.planMemberPromotion(b, source, previous)
	case "domain_alias", "optimizeip", "sctask", "dmtask":
		r.work, err = p.planTaskPromotion(b, source, previous)
	default:
		r.work, err = p.planCertPromotion(b, source, previous)
	}
	if err != nil {
		return r, err
	}
	if r.work.Conflict != "" {
		r.Reason = r.work.Conflict
		return r, nil
	}
	switch {
	case previous:
		r.Action = "unchanged"
	case r.work.Apply != nil:
		r.Action = "apply"
	default:
		r.Action = "link"
	}
	return r, nil
}

func (p *planner) planPromotions() error {
	for _, b := range p.bindings.Promotions {
		r, err := p.planPromotion(b)
		if err != nil {
			return err
		}
		if r.Action == "conflict" {
			p.report.Conflicts++
		}
		p.report.Promotions = append(p.report.Promotions, r)
	}
	return nil
}

func (r *Report) applyPromotions(ctx context.Context, tx core.App) error {
	for _, p := range r.Promotions {
		if p.Action == "unchanged" {
			continue
		}
		if p.work.Apply != nil {
			if err := p.work.Apply(ctx, tx); err != nil {
				return err
			}
		}
		b, err := json.Marshal(p.Promotion)
		if err != nil {
			return err
		}
		_, err = tx.DB().NewQuery(`INSERT INTO dns_import_promotions(source,kind,legacy_id,target_id,source_digest,binding,confirmed_at)
			VALUES({:s},{:k},{:id},{:target},{:digest},{:binding},unixepoch())`).Bind(dbx.Params{"s": r.Source, "k": p.Kind, "id": p.LegacyID, "target": p.TargetID, "digest": p.sourceDigest, "binding": string(b)}).WithContext(ctx).Execute()
		if err != nil {
			return err
		}
	}
	return nil
}
