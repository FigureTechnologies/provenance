package types

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// NewPendingRoleChangeID computes the deterministic identifier for a pending role change.
//
// The id is a hash of the registry key and the (order-independent) set of role updates, each
// reduced to its role and the order-independent set of desired addresses. Two proposals describing
// the same batch of role updates therefore collapse onto the same pending change, so their
// approvals accumulate together.
func NewPendingRoleChangeID(key *RegistryKey, roleUpdates []RoleUpdate) string {
	// Reduce each update to a canonical "role|sortedAddrs" line, then sort the lines so the id is
	// independent of both address order within a role and role order across the batch.
	lines := make([]string, len(roleUpdates))
	for i, update := range roleUpdates {
		sorted := slices.Clone(update.Addresses)
		slices.Sort(sorted)
		sorted = slices.Compact(sorted)
		lines[i] = strconv.Itoa(int(update.Role)) + "|" + strings.Join(sorted, ",")
	}
	slices.Sort(lines)

	var b strings.Builder
	b.WriteString(key.AssetClassId)
	b.WriteByte(0)
	b.WriteString(key.NftId)
	b.WriteByte(0)
	b.WriteString(strings.Join(lines, "\n"))

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// IsExpired reports whether this pending change has an expiry and the given block time is at or after it.
func (m *PendingRoleChange) IsExpired(blockTime time.Time) bool {
	return m != nil && !m.ExpiresAt.IsZero() && !blockTime.Before(m.ExpiresAt)
}

// Validate validates the PendingRoleChange. Its key, role updates, proposer, and approvals must be
// well-formed, and its id must be the deterministic id of its key and role updates.
func (m *PendingRoleChange) Validate() error {
	if m == nil {
		return fmt.Errorf("pending role change cannot be nil")
	}

	var errs []error
	keyErr := m.Key.Validate()
	if keyErr != nil {
		errs = append(errs, fmt.Errorf("key: %w", keyErr))
	}

	updateErrs := validateRoleUpdates(m.RoleUpdates)
	errs = append(errs, updateErrs...)

	if keyErr == nil && len(updateErrs) == 0 {
		if expID := NewPendingRoleChangeID(m.Key, m.RoleUpdates); m.Id != expID {
			errs = append(errs, NewErrCodeInvalidField("id", "%q does not match the key and role updates (expected %q)", m.Id, expID))
		}
	}

	if _, err := sdk.AccAddressFromBech32(m.Proposer); err != nil {
		errs = append(errs, NewErrCodeInvalidField("proposer", "%s", err))
	}

	seenApprovals := make(map[string]bool, len(m.Approvals))
	for _, approver := range m.Approvals {
		if _, err := sdk.AccAddressFromBech32(approver); err != nil {
			errs = append(errs, NewErrCodeInvalidField("approvals", "invalid address: %s", err))
			continue
		}
		if seenApprovals[approver] {
			errs = append(errs, NewErrCodeInvalidField("approvals", "duplicate address: %s", approver))
			continue
		}
		seenApprovals[approver] = true
	}

	return errors.Join(errs...)
}
