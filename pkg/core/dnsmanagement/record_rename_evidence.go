package dnsmanagement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"strings"
)

// RecordRenameEvidence captures the surrounding records before a coordinated
// rename without storing their contents.
type RecordRenameEvidence struct {
	Siblings map[string]string `json:"siblings"`
}

// ReadRecordRenameEvidence verifies the pinned source and requires the target
// to be free of the same record type or an exclusive CNAME. Call this
// immediately before dispatch, inside ReplaceVerified's edit lock.
func ReadRecordRenameEvidence(ctx context.Context, p Provider, zoneID, zoneName string, prior DNSRecord, target string, authorized func() bool) (RecordRenameEvidence, error) {
	want := prior
	want.Name = target
	if !editOwnerInZone(prior.Name, zoneName) || !editOwnerInZone(target, zoneName) || editName(prior.Name) == editName(target) || authorized == nil {
		return RecordRenameEvidence{}, ErrInvalidDNSRequest
	}
	inventory, err := inspectEdit(ctx, p, zoneID, zoneName, prior, want, authorized)
	if err != nil {
		return RecordRenameEvidence{}, err
	}
	if !renameSourceIntact(inventory, prior) || renameDestinationOccupied(inventory, want, "") {
		return RecordRenameEvidence{}, ErrRecordEditConflict
	}
	return RecordRenameEvidence{Siblings: renameSiblings(inventory, prior.ID)}, nil
}

type RecordRenameReadback struct {
	ConfirmedID  string
	CandidateID  string
	SourceIntact bool
}

// VerifyRecordRename reads provider state without submitting a write. A changed
// ID is acceptable only when an actual provider reply identified it. A new row
// of the same type and value alone does not establish its identity.
func VerifyRecordRename(ctx context.Context, p Provider, zoneID, zoneName string, prior DNSRecord, target, reportedID string, before RecordRenameEvidence, authorized func() bool) (RecordRenameReadback, error) {
	if !editOwnerInZone(prior.Name, zoneName) || !editOwnerInZone(target, zoneName) || editName(prior.Name) == editName(target) || before.Siblings == nil || authorized == nil {
		return RecordRenameReadback{}, ErrInvalidDNSRequest
	}
	want := prior
	want.Name = target
	after, err := inspectEdit(ctx, p, zoneID, zoneName, prior, want, authorized)
	if err != nil {
		return RecordRenameReadback{}, err
	}
	if !authorized() {
		return RecordRenameReadback{}, ErrRecordEditDenied
	}
	if after.matches == 1 && (after.match.ID == prior.ID || !after.hasPrior) &&
		!renameDestinationOccupied(after, want, after.match.ID) &&
		maps.Equal(before.Siblings, renameSiblings(after, after.match.ID)) {
		if after.match.ID == reportedID || reportedID == "" && after.match.ID == prior.ID {
			return RecordRenameReadback{ConfirmedID: after.match.ID}, nil
		}
		if reportedID == "" {
			return RecordRenameReadback{CandidateID: after.match.ID}, nil
		}
	}
	intact := renameSourceIntact(after, prior) && !renameDestinationOccupied(after, want, "") &&
		maps.Equal(before.Siblings, renameSiblings(after, prior.ID))
	return RecordRenameReadback{SourceIntact: intact}, nil
}

func renameSourceIntact(inv editInventory, prior DNSRecord) bool {
	return inv.hasPrior && sameEditState(inv.prior, prior) && inv.prior.UpdatedAt == prior.UpdatedAt
}

func renameDestinationOccupied(inv editInventory, want DNSRecord, exclude string) bool {
	for id, record := range inv.affected {
		if id == exclude || editName(record.Name) != editName(want.Name) {
			continue
		}
		if strings.EqualFold(record.Type, want.Type) || strings.EqualFold(record.Type, "CNAME") {
			return true
		}
	}
	return false
}

func renameSiblings(inv editInventory, exclude string) map[string]string {
	siblings := make(map[string]string, len(inv.affected))
	for id, record := range inv.affected {
		if id == exclude {
			continue
		}
		record.UpdatedAt = ""
		data, _ := json.Marshal(record)
		digest := sha256.Sum256(data)
		siblings[id] = hex.EncodeToString(digest[:])
	}
	return siblings
}
