* Evaluate each registry role assignment's `*_ANY` / `*_ALL` address condition before combining roles
  with the signature requirement type. Approving an expired pending role change now removes it without
  failing the transaction (reported via `MsgApproveRoleChangeResponse.expired` and
  `EventRoleChangeExpired`), and proposing the same role updates as an expired change replaces it with
  a new pending change.
