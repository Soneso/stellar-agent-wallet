- `ToolsetGrant` keeps its capability and destination private behind the
  `capability()` and `destination()` accessors. Deserialization and
  `ToolsetGrantStore::insert` refuse a `sign-payment` destination that is not
  a canonical G account or M address.
