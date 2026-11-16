* Evaluate each registry role assignment's `*_ANY` / `*_ALL` address condition before combining roles
  with the signature requirement type. Approving an expired pending role change now removes it without
  failing the transaction (reported via `MsgApproveRoleChangeResponse.expired` and
  `EventRoleChangeExpired`), and proposing the same role updates as an expired change replaces it with
  a new pending change.
* Validate registry pending role changes in genesis: each change must be well-formed with an id that
  matches its key and role updates, ids must be unique, and each change must target a registry entry
  in genesis that has no other pending change.
