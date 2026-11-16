package types

import "fmt"

// DefaultGenesis returns the default genesis state.
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Params: DefaultParams(),
	}
}

// Validate validates the GenesisState.
func (m *GenesisState) Validate() error {
	seenClasses := make(map[string]string, len(m.RegistryClasses))
	for _, class := range m.RegistryClasses {
		if err := class.Validate(); err != nil {
			return fmt.Errorf("registry class: %w", err)
		}
		if _, ok := seenClasses[class.RegistryClassId]; ok {
			return fmt.Errorf("duplicate registry class id: %q", class.RegistryClassId)
		}
		seenClasses[class.RegistryClassId] = class.AssetClassId
	}

	for _, entry := range m.Entries {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("entry: %w", err)
		}
		// An entry that references a registry class must reference one that exists in genesis;
		// otherwise its authorization tier would silently fall back to params/legacy at runtime.
		// The referenced class must also be for the same asset class as the entry, since a class
		// only governs entries within its own asset class.
		if entry.RegistryClassId != "" {
			classAssetClassID, ok := seenClasses[entry.RegistryClassId]
			if !ok {
				return fmt.Errorf("entry %q references unknown registry class id: %q", entry.Key.String(), entry.RegistryClassId)
			}
			if classAssetClassID != entry.Key.AssetClassId {
				return fmt.Errorf("entry %q: %w", entry.Key.String(),
					NewErrCodeRegistryClassAssetMismatch(entry.RegistryClassId, classAssetClassID, entry.Key.AssetClassId))
			}
		}
	}

	if err := m.Params.Validate(); err != nil {
		return fmt.Errorf("params: %w", err)
	}

	if err := m.validatePendingRoleChanges(); err != nil {
		return err
	}

	return nil
}

// validatePendingRoleChanges validates the genesis pending role changes. Each change must be valid,
// change ids must be unique, each change must target a registry entry in this genesis, and there may
// be at most one pending change per registry entry (matching the limit enforced at runtime).
func (m *GenesisState) validatePendingRoleChanges() error {
	entryKeys := make(map[string]bool, len(m.Entries))
	for _, entry := range m.Entries {
		entryKeys[entry.Key.String()] = true
	}

	seenIDs := make(map[string]bool, len(m.PendingRoleChanges))
	keysWithChange := make(map[string]string, len(m.PendingRoleChanges))
	for _, change := range m.PendingRoleChanges {
		if err := change.Validate(); err != nil {
			return fmt.Errorf("pending role change %q: %w", change.Id, err)
		}
		if seenIDs[change.Id] {
			return fmt.Errorf("duplicate pending role change id: %q", change.Id)
		}
		seenIDs[change.Id] = true

		key := change.Key.String()
		if !entryKeys[key] {
			return fmt.Errorf("pending role change %q references unknown registry entry %q", change.Id, key)
		}
		if otherID, ok := keysWithChange[key]; ok {
			return fmt.Errorf("pending role changes %q and %q both target registry entry %q; at most one is allowed", otherID, change.Id, key)
		}
		keysWithChange[key] = change.Id
	}
	return nil
}
