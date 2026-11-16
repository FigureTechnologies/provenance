package types

import (
	"errors"
)

// DefaultParams returns the default registry module parameters. By default the module defines no
// role authorization policies, which preserves the original chain behavior: every role change
// falls back to legacy NFT-owner authorization. Governance can install policies via
// MsgUpdateParams, and registry-class maintainers can define per-asset-class policies.
func DefaultParams() Params {
	return Params{}
}

// Validate validates the Params.
func (p Params) Validate() error {
	var errs []error
	errs = append(errs, validateRoleAuthorizations(p.RoleAuthorizations)...)
	errs = append(errs, validateNoRegistryClassRoles(p.RoleAuthorizations)...)
	if p.PendingChangeExpiry < 0 {
		errs = append(errs, NewErrCodeInvalidField("pending_change_expiry", "must be non-negative"))
	}
	return errors.Join(errs...)
}

// RoleAuthorizationMap returns a map of RegistryRole -> RoleAuthorization for the params' default
// policies, for fast lookup during authorization resolution.
func (p Params) RoleAuthorizationMap() map[RegistryRole]RoleAuthorization {
	return RoleAuthorizationMapFrom(p.RoleAuthorizations)
}

// validateNoRegistryClassRoles returns an error for every registry_class_role selector in the given
// policies. The module params policies only govern entries that are not associated with a registry
// class, so a registry_class_role selector could never resolve there.
func validateNoRegistryClassRoles(auths []RoleAuthorization) []error {
	var errs []error
	for i, auth := range auths {
		for j, path := range auth.Authorizations {
			if path == nil {
				continue
			}
			for k, req := range path.Signatures {
				if req == nil {
					continue
				}
				for l, ra := range req.Roles {
					if _, ok := ra.GetRoleSelector().(*RoleAssignment_RegistryClassRole); ok {
						errs = append(errs, NewErrCodeInvalidField("role_authorizations",
							"%d: authorization %d: signature %d: role %d: registry_class_role cannot be used in module params because they only apply to entries without a registry class",
							i, j, k, l))
					}
				}
			}
		}
	}
	return errs
}
