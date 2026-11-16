package keeper_test

import (
	"github.com/provenance-io/provenance/x/registry/types"
)

// These tests exercise the policy engine's fail-closed branches directly via
// ValidateRoleChangeAuthorization. A misconfigured policy (unspecified enums, singular assignments
// resolving to more than one address, selectors used in unsupported ways) must surface an error and
// must NEVER be silently treated as satisfied.

// engineEntry builds an in-memory registry entry (owned by s.user1) seeded with the given roles.
func (s *KeeperTestSuite) engineEntry(roles []types.RolesEntry) *types.RegistryEntry {
	return &types.RegistryEntry{
		Key:   &types.RegistryKey{AssetClassId: s.validNFTClass.Id, NftId: s.validNFT.Id},
		Roles: roles,
	}
}

// singleSigPolicy wraps one role selector in a REQUIRED_ALL single-path policy for the SERVICER role.
func singleSigPolicy(ra *types.RoleAssignment) types.RoleAuthorization {
	return types.RoleAuthorization{
		Role: types.RegistryRole_REGISTRY_ROLE_SERVICER,
		Authorizations: []*types.Authorization{{
			Description: "engine fail-closed path",
			Signatures: []*types.SignatureRequirement{{
				Type:  types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL,
				Roles: []*types.RoleAssignment{ra},
			}},
		}},
	}
}

func (s *KeeperTestSuite) TestEngine_AssignmentCurrentResolvesMultiple() {
	// CONTROLLER currently held by two addresses; singular ASSIGNMENT_CURRENT must reject.
	entry := s.engineEntry([]types.RolesEntry{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.user1, s.user2}},
	})
	policy := singleSigPolicy(&types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_CONTROLLER},
		Assignment:   types.Assignment_ASSIGNMENT_CURRENT,
	})

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1, s.user2})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "ASSIGNMENT_CURRENT for role CONTROLLER resolved to 2 addresses, expected exactly one")
}

func (s *KeeperTestSuite) TestEngine_AssignmentNewResolvesMultiple() {
	entry := s.engineEntry(nil)
	policy := singleSigPolicy(&types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_SERVICER},
		Assignment:   types.Assignment_ASSIGNMENT_NEW,
	})

	newAddrs := []string{s.user1, s.user2}
	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, newAddrs, newAddrs)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "ASSIGNMENT_NEW for role SERVICER resolved to 2 addresses, expected exactly one")
}

func (s *KeeperTestSuite) TestEngine_UnspecifiedAssignment() {
	entry := s.engineEntry([]types.RolesEntry{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.user1}},
	})
	policy := singleSigPolicy(&types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_CONTROLLER},
		Assignment:   types.Assignment_ASSIGNMENT_UNSPECIFIED,
	})

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "unsupported assignment")
}

func (s *KeeperTestSuite) TestEngine_NftRoleWithNonCurrentAssignment() {
	entry := s.engineEntry(nil)
	policy := singleSigPolicy(&types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_NftRole{NftRole: types.NftRole_NFT_ROLE_NFT_OWNER},
		Assignment:   types.Assignment_ASSIGNMENT_NEW,
	})

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "NftRole may only be used with ASSIGNMENT_CURRENT* variants")
}

func (s *KeeperTestSuite) TestEngine_UnsupportedNftRole() {
	entry := s.engineEntry(nil)
	policy := singleSigPolicy(&types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_NftRole{NftRole: types.NftRole_NFT_ROLE_UNSPECIFIED},
		Assignment:   types.Assignment_ASSIGNMENT_CURRENT,
	})

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "unsupported NftRole")
}

func (s *KeeperTestSuite) TestEngine_NoRoleSelectorSet() {
	entry := s.engineEntry(nil)
	policy := singleSigPolicy(&types.RoleAssignment{
		Assignment: types.Assignment_ASSIGNMENT_CURRENT,
	})

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "role assignment has no role selector set")
}

func (s *KeeperTestSuite) TestEngine_UnsupportedSignatureType() {
	entry := s.engineEntry([]types.RolesEntry{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.user1}},
	})
	policy := types.RoleAuthorization{
		Role: types.RegistryRole_REGISTRY_ROLE_SERVICER,
		Authorizations: []*types.Authorization{{
			Description: "bad signature type",
			Signatures: []*types.SignatureRequirement{{
				Type: types.SignatureType_SIGNATURE_TYPE_UNSPECIFIED,
				Roles: []*types.RoleAssignment{{
					RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_CONTROLLER},
					Assignment:   types.Assignment_ASSIGNMENT_CURRENT,
				}},
			}},
		}},
	}

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "unsupported signature requirement type")
}

// TestEngine_RequiredAnyIfSet_NoRolesSet confirms REQUIRED_ANY_IF_SET passes (vacuously) when none
// of its roles resolve to addresses, while REQUIRED_ANY rejects in the same situation. This is the
// empty-role distinction between the two ANY signature types.
func (s *KeeperTestSuite) TestEngine_RequiredAnyIfSet_NoRolesSet() {
	// Entry has no SECURED_PARTY_FOR_ENOTE set, so the selector resolves empty.
	entry := s.engineEntry(nil)
	selector := &types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_SECURED_PARTY_FOR_ENOTE},
		Assignment:   types.Assignment_ASSIGNMENT_CURRENT_ANY,
	}

	s.Run("required_any_if_set passes when no role resolves", func() {
		policy := types.RoleAuthorization{
			Role: types.RegistryRole_REGISTRY_ROLE_SERVICER,
			Authorizations: []*types.Authorization{{
				Signatures: []*types.SignatureRequirement{{
					Type:  types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY_IF_SET,
					Roles: []*types.RoleAssignment{selector},
				}},
			}},
		}
		err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, nil)
		s.Require().NoError(err)
	})

	s.Run("required_any rejects when no role resolves", func() {
		policy := types.RoleAuthorization{
			Role: types.RegistryRole_REGISTRY_ROLE_SERVICER,
			Authorizations: []*types.Authorization{{
				Signatures: []*types.SignatureRequirement{{
					Type:  types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY,
					Roles: []*types.RoleAssignment{selector},
				}},
			}},
		}
		err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, nil)
		s.Require().Error(err)
		s.Require().Contains(err.Error(), "no required signature found in any role")
	})
}

func (s *KeeperTestSuite) TestEngine_RegistryClassRoleWithNonCurrentAssignment() {
	entry := s.engineEntry(nil)
	policy := singleSigPolicy(&types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RegistryClassRole{RegistryClassRole: types.RegistryClassRole_REGISTRY_CLASS_ROLE_MAINTAINER},
		Assignment:   types.Assignment_ASSIGNMENT_NEW,
	})

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "RegistryClassRole may only be used with ASSIGNMENT_CURRENT* variants")
}

func (s *KeeperTestSuite) TestEngine_UnsupportedRegistryClassRole() {
	entry := s.engineEntry(nil)
	entry.RegistryClassId = "engine-class"
	policy := singleSigPolicy(&types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RegistryClassRole{RegistryClassRole: types.RegistryClassRole_REGISTRY_CLASS_ROLE_UNSPECIFIED},
		Assignment:   types.Assignment_ASSIGNMENT_CURRENT,
	})

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1})
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "unsupported RegistryClassRole")
}

// TestEngine_RegistryClassMaintainer covers how the REGISTRY_CLASS_ROLE_MAINTAINER selector resolves.
// It must fail closed (never be skipped, even by an *_IF_SET requirement) when the entry has no
// resolvable registry class or maintainer, and never fall back to any other role.
func (s *KeeperTestSuite) TestEngine_RegistryClassMaintainer() {
	maintainer := s.user2
	s.Require().NoError(s.app.RegistryKeeper.SetRegistryClass(s.ctx, types.RegistryClass{
		RegistryClassId: "engine-class",
		AssetClassId:    s.validNFTClass.Id,
		Maintainer:      maintainer,
	}))
	s.Require().NoError(s.app.RegistryKeeper.SetRegistryClass(s.ctx, types.RegistryClass{
		RegistryClassId: "engine-class-other-asset",
		AssetClassId:    "some-other-asset-class",
		Maintainer:      maintainer,
	}))

	ifSetPolicy := types.RoleAuthorization{
		Role: types.RegistryRole_REGISTRY_ROLE_SERVICER,
		Authorizations: []*types.Authorization{{
			Signatures: []*types.SignatureRequirement{{
				Type: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL_IF_SET,
				Roles: []*types.RoleAssignment{{
					RoleSelector: &types.RoleAssignment_RegistryClassRole{RegistryClassRole: types.RegistryClassRole_REGISTRY_CLASS_ROLE_MAINTAINER},
					Assignment:   types.Assignment_ASSIGNMENT_CURRENT,
				}},
			}},
		}},
	}

	tests := []struct {
		name    string
		classID string
		signers []string
		expErr  string
	}{
		{name: "maintainer signs", classID: "engine-class", signers: []string{maintainer}},
		{name: "other signer", classID: "engine-class", signers: []string{s.user1}, expErr: "missing required signature"},
		{name: "entry without a registry class", classID: "", signers: []string{s.user1, maintainer}, expErr: "not associated with a registry class"},
		{name: "registry class missing from state", classID: "missing-class", signers: []string{maintainer}, expErr: "missing-class"},
		{name: "registry class for another asset class", classID: "engine-class-other-asset", signers: []string{maintainer}, expErr: "some-other-asset-class"},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			entry := s.engineEntry(nil)
			entry.RegistryClassId = tc.classID
			err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, ifSetPolicy, entry, nil, tc.signers)
			if tc.expErr == "" {
				s.Require().NoError(err)
				return
			}
			s.Require().Error(err)
			s.Require().Contains(err.Error(), tc.expErr)
		})
	}
}

// TestEngine_AssignmentAnyAllWithSignatureType verifies that each role assignment's address-level
// condition (*_ANY: at least one address signs; *_ALL: every address signs) is evaluated first, and
// that the signature type only combines those per-role results.
func (s *KeeperTestSuite) TestEngine_AssignmentAnyAllWithSignatureType() {
	user3 := genAddr()
	entry := s.engineEntry([]types.RolesEntry{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.user1, s.user2}},
	})
	newAddrs := []string{s.user2, user3}

	tests := []struct {
		name       string
		sigType    types.SignatureType
		role       types.RegistryRole
		assignment types.Assignment
		signers    []string
		expErr     string
	}{
		{name: "required_all + current_any: one holder signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ANY, signers: []string{s.user1}},
		{name: "required_all + current_any: no holder signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ANY, signers: []string{user3}, expErr: "missing required signature from any of"},
		{name: "required_all + current_all: one holder signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ALL, signers: []string{s.user1}, expErr: "missing required signature for"},
		{name: "required_all + current_all: all holders sign", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ALL, signers: []string{s.user1, s.user2}},
		{name: "required_any + current_all: one holder signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ALL, signers: []string{s.user1}, expErr: "no required signature found in any role"},
		{name: "required_any + current_all: all holders sign", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ALL, signers: []string{s.user1, s.user2}},
		{name: "required_any + current_any: one holder signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ANY, signers: []string{s.user2}},
		{name: "required_any_if_set + current_all: one holder signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY_IF_SET, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ALL, signers: []string{s.user1}, expErr: "no required signature found in any role"},
		{name: "required_all_if_set + current_any: one holder signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL_IF_SET, role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, assignment: types.Assignment_ASSIGNMENT_CURRENT_ANY, signers: []string{s.user2}},
		{name: "required_all + new_any: one new address signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL, role: types.RegistryRole_REGISTRY_ROLE_SERVICER, assignment: types.Assignment_ASSIGNMENT_NEW_ANY, signers: []string{user3}},
		{name: "required_any + new_all: one new address signs", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY, role: types.RegistryRole_REGISTRY_ROLE_SERVICER, assignment: types.Assignment_ASSIGNMENT_NEW_ALL, signers: []string{user3}, expErr: "no required signature found in any role"},
		{name: "required_any + new_all: all new addresses sign", sigType: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY, role: types.RegistryRole_REGISTRY_ROLE_SERVICER, assignment: types.Assignment_ASSIGNMENT_NEW_ALL, signers: []string{s.user2, user3}},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			policy := types.RoleAuthorization{
				Role: types.RegistryRole_REGISTRY_ROLE_SERVICER,
				Authorizations: []*types.Authorization{{
					Signatures: []*types.SignatureRequirement{{
						Type: tc.sigType,
						Roles: []*types.RoleAssignment{{
							RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: tc.role},
							Assignment:   tc.assignment,
						}},
					}},
				}},
			}
			err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, newAddrs, tc.signers)
			if tc.expErr == "" {
				s.Require().NoError(err)
				return
			}
			s.Require().Error(err)
			s.Require().Contains(err.Error(), tc.expErr)
		})
	}
}

// TestEngine_RequiredAnyCombinesRoleResults verifies that REQUIRED_ANY passes only when at least one
// role's own assignment-level condition is satisfied, not when signatures are spread across roles.
func (s *KeeperTestSuite) TestEngine_RequiredAnyCombinesRoleResults() {
	user3 := genAddr()
	entry := s.engineEntry([]types.RolesEntry{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.user1, s.user2}},
		{Role: types.RegistryRole_REGISTRY_ROLE_PLEDGEE, Addresses: []string{user3}},
	})
	policy := types.RoleAuthorization{
		Role: types.RegistryRole_REGISTRY_ROLE_SERVICER,
		Authorizations: []*types.Authorization{{
			Signatures: []*types.SignatureRequirement{{
				Type: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY,
				Roles: []*types.RoleAssignment{
					{RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_CONTROLLER}, Assignment: types.Assignment_ASSIGNMENT_CURRENT_ALL},
					{RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_PLEDGEE}, Assignment: types.Assignment_ASSIGNMENT_CURRENT_ALL},
				},
			}},
		}},
	}

	err := s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{s.user1})
	s.Require().ErrorContains(err, "no required signature found in any role", "one of two controllers is not enough")

	s.Require().NoError(s.app.RegistryKeeper.ValidateRoleChangeAuthorization(s.ctx, policy, entry, nil, []string{user3}),
		"the pledgee alone satisfies its role")

	signers := s.app.RegistryKeeper.CollectSatisfyingSigners(s.ctx, policy, entry, nil, []string{s.user1, user3})
	s.Require().Equal([]types.RoleSigner{{
		Role:       types.RegistryRole_REGISTRY_ROLE_PLEDGEE.String(),
		Assignment: types.Assignment_ASSIGNMENT_CURRENT_ALL.String(),
		Addresses:  []string{user3},
	}}, signers, "only the satisfied role is reported")
}

// TestEngine_SignerAttributionForAnyAssignment verifies that only the holders who signed are
// reported for an *_ANY assignment.
func (s *KeeperTestSuite) TestEngine_SignerAttributionForAnyAssignment() {
	entry := s.engineEntry([]types.RolesEntry{
		{Role: types.RegistryRole_REGISTRY_ROLE_CONTROLLER, Addresses: []string{s.user1, s.user2}},
	})
	policy := singleSigPolicy(&types.RoleAssignment{
		RoleSelector: &types.RoleAssignment_RegistryRole{RegistryRole: types.RegistryRole_REGISTRY_ROLE_CONTROLLER},
		Assignment:   types.Assignment_ASSIGNMENT_CURRENT_ANY,
	})

	signers := s.app.RegistryKeeper.CollectSatisfyingSigners(s.ctx, policy, entry, nil, []string{s.user2})
	s.Require().Equal([]types.RoleSigner{{
		Role:       types.RegistryRole_REGISTRY_ROLE_CONTROLLER.String(),
		Assignment: types.Assignment_ASSIGNMENT_CURRENT_ANY.String(),
		Addresses:  []string{s.user2},
	}}, signers)
}
