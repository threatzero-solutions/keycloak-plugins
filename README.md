# Keycloak Plugins

Custom Keycloak plugins developed for the ThreatZero platform and published
open source under MIT.

## Plugins

### Identity-provider mappers

- **Advanced Claim to Attribute** (`oidc-advanced-attribute-idp-mapper`) —
  match an OIDC claim with exact / regex / glob patterns and write the
  matched value onto a user attribute.
- **Advanced Attribute to Attribute** (`saml-advanced-attribute-idp-mapper`) —
  SAML equivalent of the above.
- **Claim to User Session Note** (`oidc-claim-to-session-note-idp-mapper`) —
  plain copy of an OIDC claim value onto a user session note during
  brokered login, with no match conditions. Opt-in `json.encode` flag
  serializes lists and nested structures as JSON before writing, so
  structured claims can round-trip through the string-only session-note
  store. Pairs with a downstream protocol mapper that projects session
  notes onto issued tokens.
- **Attribute to User Session Note** (`saml-attribute-to-session-note-idp-mapper`) —
  SAML equivalent of the above, same `json.encode` flag. Fills the gap
  left by Keycloak's OIDC-only session-note IDP mapper. With the flag
  enabled, multi-valued SAML attributes preserve all values as a JSON
  array; otherwise the first value wins (legacy single-value behavior).

### Protocol mappers

- **Prefixed session notes** (`oidc-prefixed-session-note-mapper`) —
  forwards every user session note whose key starts with a configured
  prefix as a token claim. Designed for dynamic claim namespaces
  (e.g. `tz.idp.*`) where pre-authoring a mapper per claim is
  impractical. Opt-in `json.decode` flag parses session-note values as
  JSON so lists come out as real arrays on the token; falls back to a
  raw-string claim when a value isn't valid JSON, so mixing encoded and
  unencoded notes under one prefix is safe.

### Authenticators

- **Set CUID attribute** — assigns a [CUID](https://github.com/paralleldrive/cuid2)
  to a user attribute during authentication.

### Admin REST extensions

- **`GET /admin/realms/{realm}/users-by-attribute`** — paginated, filtered
  user lookup with group-membership and attribute predicates richer than
  the stock admin API exposes.

## Compatibility

Known to be compatible with Keycloak 26. Tested most recently against
26.3.3; check `keycloak.version` in `pom.xml` for the exact target.

## Build

```bash
mvn verify                       # compile, run tests, produce shaded JAR
```

The shaded artifact lands at `target/keycloak-plugins-<version>.jar`.

## Install into Keycloak

Drop the shaded JAR into `/opt/keycloak/providers/` and run
`/opt/keycloak/bin/kc.sh build` before starting Keycloak, so the SPIs are
picked up during the optimized startup.

## Release

Pushes to `main` that change `pom.xml`'s version automatically publish a
GitHub Release via `.github/workflows/ci.yml` with the shaded JAR
attached.

## License

MIT. See `LICENSE.md`.
