package keeper

import (
	"context"
	"fmt"
	"strings"

	"github.com/provenance-io/provenance/x/registry/types"
)

// resolveRegistryRoleAddresses returns the addresses for a registry role under the given
// assignment. CURRENT* variants resolve the addresses currently held for the role; NEW* variants
// resolve the incoming new addresses.
//
// The singular ASSIGNMENT_CURRENT and ASSIGNMENT_NEW variants are documented to resolve exactly
// one address and return an error if more than one would resolve.
func (k Keeper) resolveRegistryRoleAddresses(entry *types.RegistryEntry, role types.RegistryRole, assignment types.Assignment, newAddrs []string) ([]string, bool, error) {
	switch assignment {
	case types.Assignment_ASSIGNMENT_CURRENT,
		types.Assignment_ASSIGNMENT_CURRENT_ALL,
		types.Assignment_ASSIGNMENT_CURRENT_ANY:
		var current []string
		for _, re := range entry.Roles {
			if re.Role == role {
				current = re.Addresses
				break
			}
		}
		if assignment == types.Assignment_ASSIGNMENT_CURRENT && len(current) > 1 {
			return nil, false, types.NewErrCodeUnauthorized(
				fmt.Sprintf("ASSIGNMENT_CURRENT for role %s resolved to %d addresses, expected exactly one", role.ShortString(), len(current)),
			)
		}
		return current, len(current) > 0, nil
	case types.Assignment_ASSIGNMENT_NEW,
		types.Assignment_ASSIGNMENT_NEW_ALL,
		types.Assignment_ASSIGNMENT_NEW_ANY:
		if assignment == types.Assignment_ASSIGNMENT_NEW && len(newAddrs) > 1 {
			return nil, false, types.NewErrCodeUnauthorized(
				fmt.Sprintf("ASSIGNMENT_NEW for role %s resolved to %d addresses, expected exactly one", role.ShortString(), len(newAddrs)),
			)
		}
		return newAddrs, len(newAddrs) > 0, nil
	default:
		// Fail closed: an unspecified/unknown assignment is a policy misconfiguration and must not
		// silently skip a required signature check.
		return nil, false, types.NewErrCodeUnauthorized(
			fmt.Sprintf("unsupported assignment %s for role %s", assignment.String(), role.ShortString()),
		)
	}
}

// resolveNFTRoleAddresses returns the address(es) for an NFT-module role (e.g. the NFT owner).
// NftRole is read-only from the registry's perspective and may only be used with the
// ASSIGNMENT_CURRENT* variants; any other assignment is a policy misconfiguration and returns an
// error.
func (k Keeper) resolveNFTRoleAddresses(ctx context.Context, entry *types.RegistryEntry, nftRole types.NftRole, assignment types.Assignment) ([]string, bool, error) {
	switch assignment {
	case types.Assignment_ASSIGNMENT_CURRENT,
		types.Assignment_ASSIGNMENT_CURRENT_ALL,
		types.Assignment_ASSIGNMENT_CURRENT_ANY:
		// NftRole is only valid with the CURRENT* assignment variants.
	default:
		return nil, false, types.NewErrCodeUnauthorized(
			fmt.Sprintf("NftRole may only be used with ASSIGNMENT_CURRENT* variants, got %s", assignment.String()),
		)
	}

	switch nftRole {
	case types.NftRole_NFT_ROLE_NFT_OWNER:
		owner := k.GetNFTOwner(ctx, &entry.Key.AssetClassId, &entry.Key.NftId)
		if len(owner) == 0 {
			return nil, false, nil
		}
		return []string{owner.String()}, true, nil
	default:
		// Fail closed: an unspecified/unknown NftRole is a policy misconfiguration and must not
		// silently skip a required signature check.
		return nil, false, types.NewErrCodeUnauthorized(
			fmt.Sprintf("unsupported NftRole %s", nftRole.String()),
		)
	}
}

// resolveRegistryClassRoleAddresses returns the address for a registry class role (e.g. the
// maintainer of the entry's registry class). RegistryClassRole is read-only from the registry's
// perspective and may only be used with the ASSIGNMENT_CURRENT* variants. Resolution fails closed:
// an entry without a resolvable registry class (or maintainer) returns an error rather than
// resolving to no address, so it can never be skipped by an *_IF_SET requirement.
func (k Keeper) resolveRegistryClassRoleAddresses(ctx context.Context, entry *types.RegistryEntry, classRole types.RegistryClassRole, assignment types.Assignment) ([]string, bool, error) {
	if !assignment.IsCurrent() {
		return nil, false, types.NewErrCodeUnauthorized(
			fmt.Sprintf("RegistryClassRole may only be used with ASSIGNMENT_CURRENT* variants, got %s", assignment.String()),
		)
	}

	switch classRole {
	case types.RegistryClassRole_REGISTRY_CLASS_ROLE_MAINTAINER:
		maintainer, err := k.registryClassMaintainer(ctx, entry)
		if err != nil {
			return nil, false, err
		}
		return []string{maintainer}, true, nil
	default:
		// Fail closed: an unspecified/unknown RegistryClassRole is a policy misconfiguration and must
		// not silently skip a required signature check.
		return nil, false, types.NewErrCodeUnauthorized(
			fmt.Sprintf("unsupported RegistryClassRole %s", classRole.String()),
		)
	}
}

// resolveRolePriorityAddresses iterates priority entries and returns addresses from the first
// non-empty role that exists, implementing the "first match wins" fallback chain.
func (k Keeper) resolveRolePriorityAddresses(ctx context.Context, entry *types.RegistryEntry, rp *types.RolePriority, assignment types.Assignment, newAddrs []string) ([]string, bool, error) {
	if rp == nil {
		return nil, false, nil
	}
	for _, e := range rp.Entries {
		switch r := e.Role.(type) {
		case *types.RolePriorityEntry_RegistryRole:
			addrs, exists, err := k.resolveRegistryRoleAddresses(entry, r.RegistryRole, assignment, newAddrs)
			if err != nil {
				return nil, false, err
			}
			if exists {
				return addrs, true, nil
			}
		case *types.RolePriorityEntry_NftRole:
			addrs, exists, err := k.resolveNFTRoleAddresses(ctx, entry, r.NftRole, assignment)
			if err != nil {
				return nil, false, err
			}
			if exists {
				return addrs, true, nil
			}
		}
	}
	return nil, false, nil
}

// resolveRoleAssignmentAddresses dispatches to the correct resolver based on the role selector type.
func (k Keeper) resolveRoleAssignmentAddresses(ctx context.Context, entry *types.RegistryEntry, ra *types.RoleAssignment, newAddrs []string) ([]string, bool, error) {
	if ra == nil {
		return nil, false, nil
	}
	switch r := ra.RoleSelector.(type) {
	case *types.RoleAssignment_RegistryRole:
		return k.resolveRegistryRoleAddresses(entry, r.RegistryRole, ra.Assignment, newAddrs)
	case *types.RoleAssignment_NftRole:
		return k.resolveNFTRoleAddresses(ctx, entry, r.NftRole, ra.Assignment)
	case *types.RoleAssignment_RolePriority:
		return k.resolveRolePriorityAddresses(ctx, entry, r.RolePriority, ra.Assignment, newAddrs)
	case *types.RoleAssignment_RegistryClassRole:
		return k.resolveRegistryClassRoleAddresses(ctx, entry, r.RegistryClassRole, ra.Assignment)
	default:
		// Fail closed: an unset/unknown role selector is a policy misconfiguration and must not
		// silently skip a required signature check.
		return nil, false, types.NewErrCodeUnauthorized("role assignment has no role selector set")
	}
}

// assignmentNeedsAnyAddress reports whether an assignment is satisfied by a signature from any one
// of the role's resolved addresses (the *_ANY variants). Every other assignment needs a signature from
// each resolved address; the singular ASSIGNMENT_CURRENT and ASSIGNMENT_NEW resolve at most one.
func assignmentNeedsAnyAddress(assignment types.Assignment) bool {
	return assignment == types.Assignment_ASSIGNMENT_CURRENT_ANY || assignment == types.Assignment_ASSIGNMENT_NEW_ANY
}

// signedRoleAddresses evaluates a role's assignment-level condition against the signers. It returns
// the resolved addresses that signed and whether the condition is satisfied: for the *_ANY
// assignments at least one address must have signed, otherwise every address must have signed. A
// role that resolves to no addresses is never satisfied.
func signedRoleAddresses(addrs []string, assignment types.Assignment, signerSet map[string]bool) ([]string, bool) {
	var signed []string
	for _, addr := range addrs {
		if signerSet[addr] {
			signed = append(signed, addr)
		}
	}
	if assignmentNeedsAnyAddress(assignment) {
		return signed, len(signed) > 0
	}
	return signed, len(addrs) > 0 && len(signed) == len(addrs)
}

// roleAssignmentSignedError returns nil if a role's assignment-level condition is satisfied, or an
// error describing the missing signature(s) otherwise.
func roleAssignmentSignedError(addrs []string, assignment types.Assignment, signerSet map[string]bool) error {
	if _, ok := signedRoleAddresses(addrs, assignment, signerSet); ok {
		return nil
	}
	if assignmentNeedsAnyAddress(assignment) {
		return types.NewErrCodeUnauthorized(fmt.Sprintf("missing required signature from any of %q", addrs))
	}
	for _, addr := range addrs {
		if !signerSet[addr] {
			return types.NewErrCodeUnauthorized(fmt.Sprintf("missing required signature for %q", addr))
		}
	}
	return types.NewErrCodeUnauthorized("required role resolved to no addresses")
}

// evaluateSignatureRequirement checks whether a single SignatureRequirement is satisfied. Each role
// assignment is first evaluated on its own: an *_ANY assignment needs a signature from at least one
// of the role's addresses, and every other assignment needs signatures from all of them. The
// signature type then combines those per-role results:
//
//   - REQUIRED_ALL: every role must resolve to addresses and be satisfied.
//   - REQUIRED_ALL_IF_SET: every role that resolves to addresses must be satisfied; roles that
//     resolve to no addresses are skipped.
//   - REQUIRED_ANY: at least one role must resolve to addresses and be satisfied.
//   - REQUIRED_ANY_IF_SET: same as REQUIRED_ANY, but passes if no role resolves to any addresses.
func (k Keeper) evaluateSignatureRequirement(ctx context.Context, entry *types.RegistryEntry, req *types.SignatureRequirement, newAddrs []string, signerSet map[string]bool) error {
	if req == nil {
		return nil
	}
	switch req.Type {
	case types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL,
		types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL_IF_SET:
		for _, ra := range req.Roles {
			addrs, exists, err := k.resolveRoleAssignmentAddresses(ctx, entry, ra, newAddrs)
			if err != nil {
				return err
			}
			if !exists || len(addrs) == 0 {
				if req.Type == types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL_IF_SET {
					continue
				}
				return types.NewErrCodeUnauthorized("required role resolved to no addresses")
			}
			if err = roleAssignmentSignedError(addrs, ra.Assignment, signerSet); err != nil {
				return err
			}
		}

	case types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY,
		types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY_IF_SET:
		hasAnyRole := false
		for _, ra := range req.Roles {
			addrs, exists, err := k.resolveRoleAssignmentAddresses(ctx, entry, ra, newAddrs)
			if err != nil {
				return err
			}
			if !exists || len(addrs) == 0 {
				continue
			}
			hasAnyRole = true
			if _, ok := signedRoleAddresses(addrs, ra.Assignment, signerSet); ok {
				return nil
			}
		}
		if !hasAnyRole && req.Type == types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY_IF_SET {
			return nil
		}
		return types.NewErrCodeUnauthorized("no required signature found in any role")

	default:
		// Fail closed: an unspecified/unknown signature type must not be treated as satisfied.
		return types.NewErrCodeUnauthorized(
			fmt.Sprintf("unsupported signature requirement type %s", req.Type.String()),
		)
	}
	return nil
}

// evaluateAuthorization checks whether every SignatureRequirement in an authorization path is
// satisfied. Returns nil if all requirements pass, or an error describing the first failure.
func (k Keeper) evaluateAuthorization(ctx context.Context, entry *types.RegistryEntry, auth *types.Authorization, newAddrs []string, signerSet map[string]bool) error {
	if auth == nil {
		return nil
	}
	for i, req := range auth.Signatures {
		if err := k.evaluateSignatureRequirement(ctx, entry, req, newAddrs, signerSet); err != nil {
			return fmt.Errorf("signature requirement %d: %w", i, err)
		}
	}
	return nil
}

// ValidateRoleChangeAuthorization validates that the provided signers are authorized to update a
// role on the given entry. It tries each authorization path in the RoleAuthorization; the
// operation is approved as soon as any single path is fully satisfied.
//
// newAddrs contains the addresses being assigned to the role (used for ASSIGNMENT_NEW checks).
// For revoke operations, newAddrs should be nil or empty.
func (k Keeper) ValidateRoleChangeAuthorization(ctx context.Context, roleAuth types.RoleAuthorization, entry *types.RegistryEntry, newAddrs []string, signers []string) error {
	signerSet := make(map[string]bool, len(signers))
	for _, s := range signers {
		signerSet[s] = true
	}

	var pathErrors []string
	for _, auth := range roleAuth.Authorizations {
		if err := k.evaluateAuthorization(ctx, entry, auth, newAddrs, signerSet); err == nil {
			return nil
		} else {
			desc := auth.Description
			if desc == "" {
				desc = fmt.Sprintf("path %d", len(pathErrors)+1)
			}
			pathErrors = append(pathErrors, fmt.Sprintf("%s: %v", desc, err))
		}
	}

	return types.NewErrCodeUnauthorized(
		fmt.Sprintf("no valid authorization path found for %s: %s", roleAuth.Role.ShortString(), strings.Join(pathErrors, "; ")),
	)
}

// CollectPolicyApprovers returns the set of addresses that the given role authorization policy
// could ever require to sign, resolved against the entry and the addresses being newly assigned.
// These are the only approvers whose signature can contribute to satisfying the policy; any other
// address is, by definition, a no-op approver. Resolution errors from a misconfigured path are
// ignored here (the path simply contributes no eligible addresses).
func (k Keeper) CollectPolicyApprovers(ctx context.Context, roleAuth types.RoleAuthorization, entry *types.RegistryEntry, newAddrs []string) map[string]bool {
	out := make(map[string]bool)
	for _, auth := range roleAuth.Authorizations {
		if auth == nil {
			continue
		}
		for _, req := range auth.Signatures {
			if req == nil {
				continue
			}
			for _, ra := range req.Roles {
				addrs, _, _ := k.resolveRoleAssignmentAddresses(ctx, entry, ra, newAddrs)
				for _, addr := range addrs {
					out[addr] = true
				}
			}
		}
	}
	return out
}

// resolveRoleAssignmentSigner is like resolveRoleAssignmentAddresses but also returns the concrete
// role name that resolved (used to build EventRoleUpdated.signers). For a role_priority selector it
// returns the first matching priority entry's role name.
func (k Keeper) resolveRoleAssignmentSigner(ctx context.Context, entry *types.RegistryEntry, ra *types.RoleAssignment, newAddrs []string) (string, []string, bool, error) {
	if ra == nil {
		return "", nil, false, nil
	}
	switch r := ra.RoleSelector.(type) {
	case *types.RoleAssignment_RegistryRole:
		addrs, exists, err := k.resolveRegistryRoleAddresses(entry, r.RegistryRole, ra.Assignment, newAddrs)
		return r.RegistryRole.String(), addrs, exists, err
	case *types.RoleAssignment_NftRole:
		addrs, exists, err := k.resolveNFTRoleAddresses(ctx, entry, r.NftRole, ra.Assignment)
		return r.NftRole.String(), addrs, exists, err
	case *types.RoleAssignment_RolePriority:
		if r.RolePriority == nil {
			return "", nil, false, nil
		}
		for _, e := range r.RolePriority.Entries {
			switch pe := e.Role.(type) {
			case *types.RolePriorityEntry_RegistryRole:
				addrs, exists, err := k.resolveRegistryRoleAddresses(entry, pe.RegistryRole, ra.Assignment, newAddrs)
				if err != nil {
					return "", nil, false, err
				}
				if exists {
					return pe.RegistryRole.String(), addrs, true, nil
				}
			case *types.RolePriorityEntry_NftRole:
				addrs, exists, err := k.resolveNFTRoleAddresses(ctx, entry, pe.NftRole, ra.Assignment)
				if err != nil {
					return "", nil, false, err
				}
				if exists {
					return pe.NftRole.String(), addrs, true, nil
				}
			}
		}
		return "", nil, false, nil
	case *types.RoleAssignment_RegistryClassRole:
		addrs, exists, err := k.resolveRegistryClassRoleAddresses(ctx, entry, r.RegistryClassRole, ra.Assignment)
		return r.RegistryClassRole.String(), addrs, exists, err
	default:
		return "", nil, false, nil
	}
}

// collectAuthorizationSigners builds the list of RoleSigner entries describing which roles and
// addresses contributed signatures to satisfy the given (already-satisfied) authorization path.
func (k Keeper) collectAuthorizationSigners(ctx context.Context, entry *types.RegistryEntry, auth *types.Authorization, newAddrs []string, signerSet map[string]bool) []types.RoleSigner {
	var signers []types.RoleSigner
	if auth == nil {
		return signers
	}
	for _, req := range auth.Signatures {
		if req == nil {
			continue
		}
		switch req.Type {
		case types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL,
			types.SignatureType_SIGNATURE_TYPE_REQUIRED_ALL_IF_SET:
			// In a satisfied path every resolved (set) role was satisfied, so report each of them with
			// the addresses that signed for it.
			for _, ra := range req.Roles {
				name, addrs, exists, err := k.resolveRoleAssignmentSigner(ctx, entry, ra, newAddrs)
				if err != nil || !exists || len(addrs) == 0 {
					continue
				}
				if signed, ok := signedRoleAddresses(addrs, ra.Assignment, signerSet); ok {
					signers = append(signers, types.RoleSigner{Role: name, Assignment: ra.Assignment.String(), Addresses: signed})
				}
			}
		case types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY,
			types.SignatureType_SIGNATURE_TYPE_REQUIRED_ANY_IF_SET:
			// Only the first satisfied role contributed; report the addresses that signed for it.
			for _, ra := range req.Roles {
				name, addrs, exists, err := k.resolveRoleAssignmentSigner(ctx, entry, ra, newAddrs)
				if err != nil || !exists {
					continue
				}
				if signed, ok := signedRoleAddresses(addrs, ra.Assignment, signerSet); ok {
					signers = append(signers, types.RoleSigner{Role: name, Assignment: ra.Assignment.String(), Addresses: signed})
					break
				}
			}
		}
	}
	return signers
}

// CollectSatisfyingSigners finds the first authorization path satisfied by signers and returns the
// RoleSigner entries describing who authorized the change. It returns nil if no path is satisfied
// (e.g. for the legacy NFT-owner fallback, which has no policy).
func (k Keeper) CollectSatisfyingSigners(ctx context.Context, roleAuth types.RoleAuthorization, entry *types.RegistryEntry, newAddrs []string, signers []string) []types.RoleSigner {
	signerSet := make(map[string]bool, len(signers))
	for _, s := range signers {
		signerSet[s] = true
	}
	for _, auth := range roleAuth.Authorizations {
		if k.evaluateAuthorization(ctx, entry, auth, newAddrs, signerSet) == nil {
			return k.collectAuthorizationSigners(ctx, entry, auth, newAddrs, signerSet)
		}
	}
	return nil
}
