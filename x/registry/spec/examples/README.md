# Registry class examples

This directory holds example registry classes that can be created with the registry CLI.

## `example_registry_class.json`

A complete example registry class expressing the participant role policies as ordinary
`role_authorizations` data: Originator, Lien Owner (with foreclosure),
Controller (with foreclosure), Secured Party for Lien, Secured Party for eNote, Pledgee, Servicer,
and Sub-servicer.

Every policy also has a "Registry maintainer" authorization path, which the class maintainer can satisfy alone.
It uses the `registry_class_role` selector:

```json
{"registry_class_role": "REGISTRY_CLASS_ROLE_MAINTAINER", "assignment": "ASSIGNMENT_CURRENT"}
```

This selector grants no authority on its own; the maintainer can only update the roles whose policies include it.
It resolves to the maintainer of the entry's registry class, can only be used with the `ASSIGNMENT_CURRENT*` assignments, and cannot be used in the module params policies.
Remove these paths from any role the maintainer should not be able to update unilaterally.

These policies are evaluated by the registry's authorization engine; none of them are hard-coded into
the chain. A maintainer installs them per asset class:

```bash
provenanced tx registry create-registry-class example_registry_class.json --from <maintainer-key>
```

Before submitting, set `registry_class_id`, `asset_class_id`, and `maintainer` to your values (the
`maintainer` must equal the `--from` signer, or it can be omitted to default to that signer).

The file is kept in sync with the policy builders in
`x/registry/keeper/participant_role_policies_acceptance_test.go`; regenerate it with:

```bash
REGEN_EXAMPLE_FIXTURE=1 go test ./x/registry/keeper/ -run TestParticipantRolePoliciesAcceptanceTestSuite/TestExampleFixtureInSync
```
