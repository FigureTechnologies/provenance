package types_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/provenance-io/provenance/x/registry/types"
)

func TestParams_Validate(t *testing.T) {
	maintainerPolicy := func() types.RoleAuthorization {
		ra := validRoleAuthorization()
		ra.Authorizations = append(ra.Authorizations, &types.Authorization{
			Description: "registry maintainer",
			Signatures: []*types.SignatureRequirement{{
				Type: types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL,
				Roles: []*types.RoleAssignment{{
					RoleSelector: &types.RoleAssignment_RegistryClassRole{RegistryClassRole: types.RegistryClassRole_REGISTRY_CLASS_ROLE_MAINTAINER},
					Assignment:   types.Assignment_ASSIGNMENT_CURRENT,
				}},
			}},
		})
		return ra
	}

	tests := []struct {
		name   string
		params types.Params
		expErr string
	}{
		{
			name:   "default",
			params: types.DefaultParams(),
		},
		{
			name:   "valid role authorizations",
			params: types.Params{RoleAuthorizations: []types.RoleAuthorization{validRoleAuthorization()}},
		},
		{
			name:   "registry_class_role is rejected",
			params: types.Params{RoleAuthorizations: []types.RoleAuthorization{maintainerPolicy()}},
			expErr: "0: authorization 1: signature 0: role 0: registry_class_role cannot be used in module params",
		},
		{
			name:   "negative pending change expiry",
			params: types.Params{PendingChangeExpiry: -1},
			expErr: "pending_change_expiry",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.Validate()
			if tc.expErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.expErr)
		})
	}
}
