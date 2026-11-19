package dnsmigrate

import (
	"context"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// A member mapping verifies an identity provisioned by the administrator. Login
// credentials, member flags and workspace memberships remain under native control.
func (p *planner) planMemberPromotion(b Promotion, source Item, previouslyApplied bool) (promotionWork, error) {
	row := source.details.(Related)
	switch row.Kind {
	case "user":
		if b.Role != "" {
			return promotionWork{Conflict: "a member mapping cannot assign a role"}, nil
		}
		return p.checkMappedMember(row, b.TargetID, false)
	case "permission":
		return p.planZoneGrant(b, row, previouslyApplied)
	default:
		return promotionWork{Conflict: "unsupported member mapping"}, nil
	}
}

func (p *planner) checkMappedMember(user Related, memberID string, grant bool) (promotionWork, error) {
	if user.State != 0 && user.State != 1 {
		return promotionWork{Conflict: "unknown legacy user status"}, nil
	}
	disabled, found, err := p.scalar("SELECT CASE WHEN disabled=0 THEN '0' ELSE '1' END FROM dns_members WHERE id={:id}", dbx.Params{"id": memberID})
	if err != nil {
		return promotionWork{}, err
	}
	if !found {
		return promotionWork{Conflict: "target DNS member does not exist"}, nil
	}
	if user.State == 0 && disabled == "0" {
		return promotionWork{Conflict: "disabled source identity requires a disabled target member"}, nil
	}
	if grant && (user.State != 1 || disabled != "0") {
		return promotionWork{Conflict: "permission requires an enabled source user and target DNS member"}, nil
	}
	return promotionWork{}, nil
}

func (p *planner) planZoneGrant(b Promotion, permission Related, previouslyApplied bool) (promotionWork, error) {
	if b.Role != "reader" && b.Role != "editor" {
		return promotionWork{Conflict: "select reader or editor explicitly for the zone grant"}, nil
	}
	if permission.RR != "" {
		return promotionWork{Conflict: "record-scoped permissions cannot become whole-zone grants"}, nil
	}
	user, ok := p.sourceItem("user", permission.ParentID)
	memberID, selected := p.promotionTarget("user", permission.ParentID)
	if !ok || !selected {
		return promotionWork{Conflict: "select the source user's DNS member mapping"}, nil
	}
	check, err := p.checkMappedMember(user.details.(Related), memberID, true)
	if err != nil || check.Conflict != "" {
		return check, err
	}

	// A source permission identifies a DNS name. When several accounts contain
	// that name, only the explicitly selected local zone may receive the grant.
	valid := false
	for _, zone := range p.manifest.Zones {
		if zone.Name != permission.Domain {
			continue
		}
		mapped, ok := p.sourceItem("domain", zone.ID)
		if ok && mapped.Action != "conflict" && mapped.AccountID != "" && mapped.Target == b.TargetID {
			valid = true
			break
		}
	}
	if !valid {
		return promotionWork{Conflict: "target zone must match a mapped source domain and its account"}, nil
	}

	for _, other := range p.bindings.Promotions {
		if other.Kind != "permission" || other.LegacyID == b.LegacyID || other.TargetID != b.TargetID {
			continue
		}
		s, ok := p.sourceItem("permission", other.LegacyID)
		if ok && s.details.(Related).ParentID == permission.ParentID {
			return promotionWork{Conflict: "multiple source permissions select the same member and zone"}, nil
		}
	}

	_, claimed, err := p.scalar(`SELECT 1 FROM dns_import_promotions p
		JOIN dns_import_items i USING (source,kind,legacy_id)
		WHERE p.source={:source} AND p.kind='permission' AND p.target_id={:zone}
		AND p.legacy_id<>{:id} AND json_extract(i.details,'$.parentId')={:user}
		LIMIT 1`, dbx.Params{"source": p.manifest.Source, "zone": b.TargetID, "id": b.LegacyID, "user": permission.ParentID})
	if err != nil {
		return promotionWork{}, err
	}
	if claimed {
		return promotionWork{Conflict: "member and zone already confirmed for another source permission"}, nil
	}

	// Reconcile against the unique (member, zone) relation. Later revocation
	// or role changes require a new grant decision outside the importer.
	role, exists, err := p.scalar("SELECT role FROM dns_zone_grants WHERE member={:member} AND zone={:zone}",
		dbx.Params{"member": memberID, "zone": b.TargetID})
	if err != nil {
		return promotionWork{}, err
	}
	if exists {
		if role != b.Role {
			return promotionWork{Conflict: "existing zone grant has a different role"}, nil
		}
		return promotionWork{}, nil
	}
	if previouslyApplied {
		return promotionWork{Conflict: "previously mapped zone grant was revoked"}, nil
	}
	return promotionWork{Apply: func(ctx context.Context, tx core.App) error {
		grants, err := tx.FindCollectionByNameOrId("dns_zone_grants")
		if err != nil {
			return err
		}
		g := core.NewRecord(grants)
		g.Set("member", memberID)
		g.Set("zone", b.TargetID)
		g.Set("role", b.Role)
		return tx.SaveWithContext(ctx, g)
	}}, nil
}
