package types_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/provenance-io/provenance/x/registry/types"
)

// validPendingRoleChange returns a well-formed pending role change for key, with a matching id.
func validPendingRoleChange(key *types.RegistryKey) types.PendingRoleChange {
	proposer := sdk.AccAddress("pending_proposer_____").String()
	updates := []types.RoleUpdate{
		{Role: types.RegistryRole_REGISTRY_ROLE_SERVICER, Addresses: []string{sdk.AccAddress("pending_servicer_____").String()}},
	}
	return types.PendingRoleChange{
		Id:          types.NewPendingRoleChangeID(key, updates),
		Key:         key,
		RoleUpdates: updates,
		Proposer:    proposer,
		Approvals:   []string{proposer},
	}
}

func TestPendingRoleChange_Validate(t *testing.T) {
	key := &types.RegistryKey{AssetClassId: "class1", NftId: "nft1"}
	otherAddr := sdk.AccAddress("pending_other________").String()

	tests := []struct {
		name   string
		mutate func(c *types.PendingRoleChange)
		expErr string
	}{
		{name: "valid", mutate: func(_ *types.PendingRoleChange) {}},
		{
			name:   "nil key",
			mutate: func(c *types.PendingRoleChange) { c.Key = nil },
			expErr: "registry key cannot be nil",
		},
		{
			name:   "no role updates",
			mutate: func(c *types.PendingRoleChange) { c.RoleUpdates = nil },
			expErr: "at least one role update is required",
		},
		{
			name:   "invalid role update address",
			mutate: func(c *types.PendingRoleChange) { c.RoleUpdates[0].Addresses = []string{"bad-address"} },
			expErr: "invalid address",
		},
		{
			name:   "id does not match key and role updates",
			mutate: func(c *types.PendingRoleChange) { c.Id = "not-the-id" },
			expErr: "does not match the key and role updates",
		},
		{
			name: "id for a different key",
			mutate: func(c *types.PendingRoleChange) {
				c.Key = &types.RegistryKey{AssetClassId: "class1", NftId: "nft2"}
			},
			expErr: "does not match the key and role updates",
		},
		{
			name:   "invalid proposer",
			mutate: func(c *types.PendingRoleChange) { c.Proposer = "bad-address" },
			expErr: "proposer",
		},
		{
			name:   "invalid approval",
			mutate: func(c *types.PendingRoleChange) { c.Approvals = append(c.Approvals, "bad-address") },
			expErr: "approvals",
		},
		{
			name:   "duplicate approval",
			mutate: func(c *types.PendingRoleChange) { c.Approvals = []string{otherAddr, otherAddr} },
			expErr: "duplicate address",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			change := validPendingRoleChange(key)
			tc.mutate(&change)
			err := change.Validate()
			if tc.expErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.expErr)
		})
	}
}

func TestGenesisState_Validate_PendingRoleChanges(t *testing.T) {
	key1 := &types.RegistryKey{AssetClassId: "class1", NftId: "nft1"}
	key2 := &types.RegistryKey{AssetClassId: "class1", NftId: "nft2"}
	entryAddr := sdk.AccAddress("pending_entry_holder_").String()
	entry := func(key *types.RegistryKey) types.RegistryEntry {
		return types.RegistryEntry{
			Key:   key,
			Roles: []types.RolesEntry{{Role: types.RegistryRole_REGISTRY_ROLE_ORIGINATOR, Addresses: []string{entryAddr}}},
		}
	}
	secondChange := func(key *types.RegistryKey) types.PendingRoleChange {
		change := validPendingRoleChange(key)
		change.RoleUpdates = []types.RoleUpdate{{Role: types.RegistryRole_REGISTRY_ROLE_SUBSERVICER, Addresses: []string{entryAddr}}}
		change.Id = types.NewPendingRoleChangeID(key, change.RoleUpdates)
		return change
	}

	tests := []struct {
		name    string
		genesis types.GenesisState
		expErr  string
	}{
		{
			name: "valid pending changes for different entries",
			genesis: types.GenesisState{
				Entries:            []types.RegistryEntry{entry(key1), entry(key2)},
				PendingRoleChanges: []types.PendingRoleChange{validPendingRoleChange(key1), validPendingRoleChange(key2)},
			},
		},
		{
			name: "invalid pending change",
			genesis: types.GenesisState{
				Entries: []types.RegistryEntry{entry(key1)},
				PendingRoleChanges: []types.PendingRoleChange{func() types.PendingRoleChange {
					c := validPendingRoleChange(key1)
					c.Id = "not-the-id"
					return c
				}()},
			},
			expErr: "pending role change \"not-the-id\": ",
		},
		{
			name: "duplicate pending change id",
			genesis: types.GenesisState{
				Entries:            []types.RegistryEntry{entry(key1)},
				PendingRoleChanges: []types.PendingRoleChange{validPendingRoleChange(key1), validPendingRoleChange(key1)},
			},
			expErr: "duplicate pending role change id",
		},
		{
			name: "pending change for unknown entry",
			genesis: types.GenesisState{
				Entries:            []types.RegistryEntry{entry(key1)},
				PendingRoleChanges: []types.PendingRoleChange{validPendingRoleChange(key2)},
			},
			expErr: "references unknown registry entry",
		},
		{
			name: "two pending changes for one entry",
			genesis: types.GenesisState{
				Entries:            []types.RegistryEntry{entry(key1)},
				PendingRoleChanges: []types.PendingRoleChange{validPendingRoleChange(key1), secondChange(key1)},
			},
			expErr: "at most one is allowed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.genesis.Validate()
			if tc.expErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.expErr)
		})
	}
}
