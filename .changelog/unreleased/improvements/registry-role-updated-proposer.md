* Add `proposer` to the registry module's `EventRoleUpdated`. For changes applied via the propose/approve
  flow it is the `MsgProposeRoleChange` signer; for `MsgGrantRole`, `MsgRevokeRole`, and `MsgSetRoles` it is
  the message signer. When executed via authz, it is the granter rather than the grantee.
