* Add the `REGISTRY_CLASS_ROLE_MAINTAINER` registry class role selector so a registry class can opt role
  policies into an authorization path satisfied by the class maintainer. Only the class maintainer may
  unregister an NFT whose registry entry is associated with a registry class, and the class maintainer
  may also cancel pending role changes on those entries.
