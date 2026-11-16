package keeper_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"cosmossdk.io/x/nft"
	nftkeeper "cosmossdk.io/x/nft/keeper"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/provenance-io/provenance/app"
	"github.com/provenance-io/provenance/x/registry/keeper"
	"github.com/provenance-io/provenance/x/registry/types"
)

// RegistryClassMaintainerAcceptanceTestSuite covers the REGISTRY_CLASS_ROLE_MAINTAINER selector,
// which lets a registry class opt specific role policies into an alternative authorization path
// satisfied by the class maintainer alone, plus the maintainer's authority over UnregisterNFT and
// CancelRoleChange for entries associated with the class.
type RegistryClassMaintainerAcceptanceTestSuite struct {
	suite.Suite

	app *app.App
	ctx sdk.Context

	registryKeeper keeper.Keeper
	nftKeeper      nftkeeper.Keeper
	msgServer      types.MsgServer
	queryServer    *keeper.QueryServer

	nftClass nft.Class

	nftOwner      string
	maintainer    string
	controller    string
	newController string
	stranger      string
}

const maintainerTestClassID = "maintainer-class"

func TestRegistryClassMaintainerAcceptanceTestSuite(t *testing.T) {
	suite.Run(t, new(RegistryClassMaintainerAcceptanceTestSuite))
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) SetupTest() {
	s.app = app.Setup(s.T())
	s.ctx = s.app.BaseApp.NewContextLegacy(false, cmtproto.Header{Time: time.Now()}).WithBlockTime(time.Now())

	s.nftKeeper = s.app.NFTKeeper
	s.registryKeeper = s.app.RegistryKeeper
	s.msgServer = keeper.NewMsgServer(s.registryKeeper)
	s.queryServer = keeper.NewQueryServer(s.registryKeeper)

	s.nftOwner = genAddr()
	s.maintainer = genAddr()
	s.controller = genAddr()
	s.newController = genAddr()
	s.stranger = genAddr()

	s.nftClass = nft.Class{Id: "maintainer-test-nft-class"}
	s.nftKeeper.SaveClass(s.ctx, s.nftClass)

	_, err := s.msgServer.CreateRegistryClass(s.ctx, &types.MsgCreateRegistryClass{
		Signer:             s.maintainer,
		RegistryClassId:    maintainerTestClassID,
		AssetClassId:       s.nftClass.Id,
		Maintainer:         s.maintainer,
		RoleAuthorizations: maintainerTestRoleAuthorizations(),
	})
	s.Require().NoError(err)
}

// maintainerSelector returns a REGISTRY_CLASS_ROLE_MAINTAINER selector with ASSIGNMENT_CURRENT.
func maintainerSelector() *types.RoleAssignment {
	return &types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RegistryClassRole{
			RegistryClassRole: types.RegistryClassRole_REGISTRY_CLASS_ROLE_MAINTAINER,
		},
		Assignment: types.Assignment_ASSIGNMENT_CURRENT,
	}
}

// currentControllerOrOwner returns a role_priority selector for the current CONTROLLER, falling
// back to the NFT owner.
func currentControllerOrOwner() *types.RoleAssignment {
	return &types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RolePriority{
			RolePriority: &types.RolePriority{
				Entries: []*types.RolePriorityEntry{
					{Role: &types.RolePriorityEntry_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_CONTROLLER}},
					{Role: &types.RolePriorityEntry_NftRole{NftRole: types.NftRole_NFT_ROLE_NFT_OWNER}},
				},
			},
		},
		Assignment: types.Assignment_ASSIGNMENT_CURRENT,
	}
}

// maintainerPath returns an authorization path satisfied by the registry class maintainer alone.
func maintainerPath() *types.Authorization {
	return &types.Authorization{
		Description: "Registry maintainer",
		Signatures: []*types.SignatureRequirement{
			{
				Type:  types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL,
				Roles: []*types.RoleAssignment{maintainerSelector()},
			},
		},
	}
}

// maintainerTestRoleAuthorizations returns the class policies used by this suite:
//   - CONTROLLER: a normal transfer path (current + new controller) plus the maintainer path.
//   - SERVICER: only the current controller (or NFT owner); no maintainer path.
//
// Every other role has no policy and falls back to the legacy NFT-owner authorization.
func maintainerTestRoleAuthorizations() []types.RoleAuthorization {
	return []types.RoleAuthorization{
		{
			Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER,
			Authorizations: []*types.Authorization{
				{
					Description: "Normal controller transfer",
					Signatures: []*types.SignatureRequirement{
						{
							Type:  types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL,
							Roles: []*types.RoleAssignment{currentControllerOrOwner()},
						},
						{
							Type: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL_IF_SET,
							Roles: []*types.RoleAssignment{
								{
									RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_CONTROLLER},
									Assignment:   types.Assignment_ASSIGNMENT_NEW,
								},
							},
						},
					},
				},
				maintainerPath(),
			},
		},
		{
			Role: types.RegistryRole_REGISTRY_ROLE_SERVICER,
			Authorizations: []*types.Authorization{
				{
					Description: "Current controller or NFT owner",
					Signatures: []*types.SignatureRequirement{
						{
							Type:  types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL,
							Roles: []*types.RoleAssignment{currentControllerOrOwner()},
						},
					},
				},
			},
		},
	}
}

// registerClassed mints an NFT owned by s.nftOwner and registers it in the suite's registry class
// with s.controller as the CONTROLLER.
func (s *RegistryClassMaintainerAcceptanceTestSuite) registerClassed(id string) *types.RegistryKey {
	return s.registerWithClass(id, maintainerTestClassID)
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) registerWithClass(id, classID string) *types.RegistryKey {
	n := nft.NFT{ClassId: s.nftClass.Id, Id: id}
	ownerAddr, err := sdk.AccAddressFromBech32(s.nftOwner)
	s.Require().NoError(err)
	s.Require().NoError(s.nftKeeper.Mint(s.ctx, n, ownerAddr))
	key := &types.RegistryKey{AssetClassId: s.nftClass.Id, NftId: id}
	_, err = s.msgServer.RegisterNFT(s.ctx, &types.MsgRegisterNFT{
		Signer:          s.nftOwner,
		Key:             key,
		Roles:           []types.RolesEntry{{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.controller}}},
		RegistryClassId: classID,
	})
	s.Require().NoError(err)
	return key
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) roleAddrs(key *types.RegistryKey, role types.RegistryRole) []string {
	entry, err := s.registryKeeper.GetRegistry(s.ctx, key)
	s.Require().NoError(err)
	s.Require().NotNil(entry)
	return entry.GetRoleAddrs(role)
}

// roleUpdatedEvents returns all EventRoleUpdated emitted on the suite's context.
func (s *RegistryClassMaintainerAcceptanceTestSuite) roleUpdatedEvents() []*types.EventRoleUpdated {
	var out []*types.EventRoleUpdated
	for _, e := range s.ctx.EventManager().Events() {
		if e.Type != "provenance.registry.v1.EventRoleUpdated" {
			continue
		}
		msg, err := sdk.ParseTypedEvent(abci.Event{Type: e.Type, Attributes: e.Attributes})
		s.Require().NoError(err)
		ev, ok := msg.(*types.EventRoleUpdated)
		s.Require().True(ok)
		out = append(out, ev)
	}
	return out
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) requireMaintainerSigner(ev *types.EventRoleUpdated) {
	s.Require().Equal(maintainerTestClassID, ev.RegistryClassId)
	s.Require().Equal([]types.RoleSigner{{
		Role:       "REGISTRY_CLASS_ROLE_MAINTAINER",
		Assignment: "ASSIGNMENT_CURRENT",
		Addresses:  []string{s.maintainer},
	}}, ev.Signers)
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) TestSetRoles_MaintainerPath() {
	key := s.registerClassed("nft-set-roles")

	s.ctx = s.ctx.WithEventManager(sdk.NewEventManager())
	_, err := s.msgServer.SetRoles(s.ctx, &types.MsgSetRoles{
		Signer: s.maintainer,
		Key:    key,
		RoleUpdates: []types.RoleUpdate{
			{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.newController}},
		},
	})
	s.Require().NoError(err, "maintainer must satisfy the CONTROLLER policy through the maintainer path")
	s.Require().Equal([]string{s.newController}, s.roleAddrs(key, types.RegistryRole_REGISTRY_ROLE_CONTROLLER))

	evts := s.roleUpdatedEvents()
	s.Require().Len(evts, 1)
	s.Require().Equal([]string{s.controller}, evts[0].PreviousAddresses)
	s.Require().Equal([]string{s.newController}, evts[0].Addresses)
	s.requireMaintainerSigner(evts[0])
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) TestGrantAndRevokeRole_MaintainerPath() {
	key := s.registerClassed("nft-grant-revoke")

	s.Run("maintainer revokes the current controller", func() {
		s.ctx = s.ctx.WithEventManager(sdk.NewEventManager())
		_, err := s.msgServer.RevokeRole(s.ctx, &types.MsgRevokeRole{
			Signer:    s.maintainer,
			Key:       key,
			Role:      types.RegistryRole_REGISTRY_ROLE_CONTROLLER,
			Addresses: []string{s.controller},
		})
		s.Require().NoError(err)
		s.Require().Empty(s.roleAddrs(key, types.RegistryRole_REGISTRY_ROLE_CONTROLLER))

		evts := s.roleUpdatedEvents()
		s.Require().Len(evts, 1)
		s.requireMaintainerSigner(evts[0])
	})

	s.Run("maintainer grants a new controller", func() {
		s.ctx = s.ctx.WithEventManager(sdk.NewEventManager())
		_, err := s.msgServer.GrantRole(s.ctx, &types.MsgGrantRole{
			Signer:    s.maintainer,
			Key:       key,
			Role:      types.RegistryRole_REGISTRY_ROLE_CONTROLLER,
			Addresses: []string{s.newController},
		})
		s.Require().NoError(err)
		s.Require().Equal([]string{s.newController}, s.roleAddrs(key, types.RegistryRole_REGISTRY_ROLE_CONTROLLER))

		evts := s.roleUpdatedEvents()
		s.Require().Len(evts, 1)
		s.requireMaintainerSigner(evts[0])
	})

	s.Run("stranger cannot use the maintainer path", func() {
		_, err := s.msgServer.GrantRole(s.ctx, &types.MsgGrantRole{
			Signer:    s.stranger,
			Key:       key,
			Role:      types.RegistryRole_REGISTRY_ROLE_CONTROLLER,
			Addresses: []string{s.stranger},
		})
		s.Require().Error(err)
		s.Require().ErrorContains(err, "no valid authorization path found for CONTROLLER")
	})
}

// TestMaintainerPathIsOptIn verifies that the maintainer has no authority over roles whose policy
// does not include a maintainer path, or roles with no policy at all.
func (s *RegistryClassMaintainerAcceptanceTestSuite) TestMaintainerPathIsOptIn() {
	key := s.registerClassed("nft-opt-in")

	s.Run("role policy without a maintainer path", func() {
		_, err := s.msgServer.GrantRole(s.ctx, &types.MsgGrantRole{
			Signer:    s.maintainer,
			Key:       key,
			Role:      types.RegistryRole_REGISTRY_ROLE_SERVICER,
			Addresses: []string{s.stranger},
		})
		s.Require().Error(err)
		s.Require().ErrorContains(err, "no valid authorization path found for SERVICER")
	})

	s.Run("role without a policy falls back to the NFT owner", func() {
		_, err := s.msgServer.GrantRole(s.ctx, &types.MsgGrantRole{
			Signer:    s.maintainer,
			Key:       key,
			Role:      types.RegistryRole_REGISTRY_ROLE_BORROWER,
			Addresses: []string{s.stranger},
		})
		s.Require().Error(err)
		s.Require().ErrorContains(err, "signer does not own the NFT")
	})

	s.Run("set roles is atomic across a permitted and a non-permitted role", func() {
		_, err := s.msgServer.SetRoles(s.ctx, &types.MsgSetRoles{
			Signer: s.maintainer,
			Key:    key,
			RoleUpdates: []types.RoleUpdate{
				{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.newController}},
				{Role: types.RegistryRole_REGISTRY_ROLE_SERVICER, Addresses: []string{s.stranger}},
			},
		})
		s.Require().Error(err)
		s.Require().Equal([]string{s.controller}, s.roleAddrs(key, types.RegistryRole_REGISTRY_ROLE_CONTROLLER))
		s.Require().Empty(s.roleAddrs(key, types.RegistryRole_REGISTRY_ROLE_SERVICER))
	})
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) TestProposeRoleChange_MaintainerAppliesImmediately() {
	key := s.registerClassed("nft-propose")

	_, applied, err := s.registryKeeper.ProposeRoleChange(s.ctx, s.maintainer, key, []types.RoleUpdate{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.newController}},
	})
	s.Require().NoError(err)
	s.Require().True(applied, "the maintainer alone satisfies the maintainer path")
	s.Require().Equal([]string{s.newController}, s.roleAddrs(key, types.RegistryRole_REGISTRY_ROLE_CONTROLLER))
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) TestApproveRoleChange_MaintainerCompletesPendingChange() {
	key := s.registerClassed("nft-approve")

	// The current controller proposes a transfer; the normal path still needs the new controller.
	changeID, applied, err := s.registryKeeper.ProposeRoleChange(s.ctx, s.controller, key, []types.RoleUpdate{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.newController}},
	})
	s.Require().NoError(err)
	s.Require().False(applied)

	s.ctx = s.ctx.WithEventManager(sdk.NewEventManager())
	applied, _, err = s.registryKeeper.ApproveRoleChange(s.ctx, s.maintainer, changeID)
	s.Require().NoError(err)
	s.Require().True(applied, "the maintainer's approval satisfies the maintainer path")
	s.Require().Equal([]string{s.newController}, s.roleAddrs(key, types.RegistryRole_REGISTRY_ROLE_CONTROLLER))

	evts := s.roleUpdatedEvents()
	s.Require().Len(evts, 1)
	s.requireMaintainerSigner(evts[0])
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) TestValidateRoleChange_MaintainerPath() {
	key := s.registerClassed("nft-validate")
	updates := []types.RoleUpdate{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.newController}},
	}

	resp, err := s.queryServer.ValidateRoleChange(s.ctx, &types.QueryValidateRoleChangeRequest{
		Key: key, RoleUpdates: updates, Approvers: []string{s.maintainer},
	})
	s.Require().NoError(err)
	s.Require().True(resp.Authorized, resp.Error)

	resp, err = s.queryServer.ValidateRoleChange(s.ctx, &types.QueryValidateRoleChangeRequest{
		Key: key, RoleUpdates: updates, Approvers: []string{s.stranger},
	})
	s.Require().NoError(err)
	s.Require().False(resp.Authorized)
}

// TestMaintainerPath_FailsClosedOnInvalidMaintainer verifies that a class whose maintainer cannot be
// resolved fails the maintainer path without blocking the role's other authorization paths.
func (s *RegistryClassMaintainerAcceptanceTestSuite) TestMaintainerPath_FailsClosedOnInvalidMaintainer() {
	const badClassID = "bad-maintainer-class"
	s.Require().NoError(s.registryKeeper.SetRegistryClass(s.ctx, types.RegistryClass{
		RegistryClassId:    badClassID,
		AssetClassId:       s.nftClass.Id,
		Maintainer:         "not-an-address",
		RoleAuthorizations: maintainerTestRoleAuthorizations(),
	}))
	key := s.registerWithClass("nft-bad-maintainer", badClassID)

	_, err := s.msgServer.RevokeRole(s.ctx, &types.MsgRevokeRole{
		Signer:    s.stranger,
		Key:       key,
		Role:      types.RegistryRole_REGISTRY_ROLE_CONTROLLER,
		Addresses: []string{s.controller},
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, "invalid maintainer address")

	_, err = s.msgServer.RevokeRole(s.ctx, &types.MsgRevokeRole{
		Signer:    s.controller,
		Key:       key,
		Role:      types.RegistryRole_REGISTRY_ROLE_CONTROLLER,
		Addresses: []string{s.controller},
	})
	s.Require().NoError(err, "the normal path must still be evaluated when the maintainer path fails")

	_, err = s.msgServer.UnregisterNFT(s.ctx, &types.MsgUnregisterNFT{Signer: s.nftOwner, Key: key})
	s.Require().Error(err)
	s.Require().ErrorContains(err, "invalid maintainer address")
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) TestUnregisterNFT_ClassEntryRequiresMaintainer() {
	key := s.registerClassed("nft-unregister")

	_, err := s.msgServer.UnregisterNFT(s.ctx, &types.MsgUnregisterNFT{Signer: s.nftOwner, Key: key})
	s.Require().Error(err, "NFT owner must not unregister a class entry")
	s.Require().ErrorContains(err, "signer is not the registry class maintainer")

	_, err = s.msgServer.UnregisterNFT(s.ctx, &types.MsgUnregisterNFT{Signer: s.controller, Key: key})
	s.Require().Error(err, "controller must not unregister a class entry")
	s.Require().ErrorContains(err, "signer is not the registry class maintainer")

	_, err = s.msgServer.UnregisterNFT(s.ctx, &types.MsgUnregisterNFT{Signer: s.maintainer, Key: key})
	s.Require().NoError(err)

	entry, err := s.registryKeeper.GetRegistry(s.ctx, key)
	s.Require().NoError(err)
	s.Require().Nil(entry)
}

func (s *RegistryClassMaintainerAcceptanceTestSuite) TestCancelRoleChange_Maintainer() {
	key := s.registerClassed("nft-cancel")
	propose := func() string {
		changeID, applied, err := s.registryKeeper.ProposeRoleChange(s.ctx, s.controller, key, []types.RoleUpdate{
			{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.newController}},
		})
		s.Require().NoError(err)
		s.Require().False(applied)
		return changeID
	}
	requireGone := func(changeID string) {
		change, err := s.registryKeeper.GetPendingRoleChange(s.ctx, changeID)
		s.Require().NoError(err)
		s.Require().Nil(change)
	}

	s.Run("stranger cannot cancel", func() {
		changeID := propose()
		_, err := s.msgServer.CancelRoleChange(s.ctx, &types.MsgCancelRoleChange{Signer: s.stranger, ChangeId: changeID})
		s.Require().Error(err)
		s.Require().ErrorContains(err, "only the original proposer or the registry class maintainer may cancel")

		_, err = s.msgServer.CancelRoleChange(s.ctx, &types.MsgCancelRoleChange{Signer: s.controller, ChangeId: changeID})
		s.Require().NoError(err, "proposer must still be able to cancel")
		requireGone(changeID)
	})

	s.Run("maintainer can cancel", func() {
		changeID := propose()
		_, err := s.msgServer.CancelRoleChange(s.ctx, &types.MsgCancelRoleChange{Signer: s.maintainer, ChangeId: changeID})
		s.Require().NoError(err)
		requireGone(changeID)
	})
}
