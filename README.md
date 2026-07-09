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
- **Claim to Attribute** (`oidc-claim-to-attribute-idp-mapper`) —
  plain copy of an OIDC claim value onto a persisted user attribute
  during brokered login, with no match conditions. Same `json.encode`
  flag as the session-note variant for structured round-trips. With
  sync mode FORCE the attribute is *removed* when the claim is absent,
  so it tracks the identity provider's current truth on every login.
  Pairs with `oidc-prefixed-attribute-mapper`. Note: the realm must
  permit the target attribute under Keycloak's declarative user profile
  (declare it, or set `unmanagedAttributePolicy=ADMIN_EDIT`), or the
  write is silently dropped.
- **Attribute to Attribute** (`saml-attribute-to-attribute-idp-mapper`) —
  SAML equivalent of the above: plain copy of a SAML assertion attribute
  onto a persisted user attribute, same `json.encode` flag (multi-valued
  attributes preserved as a JSON array; otherwise first value wins) and
  same FORCE clear-on-absent semantics. Same realm user-profile
  prerequisite.

### Protocol mappers

- **Prefixed session notes** (`oidc-prefixed-session-note-mapper`) —
  forwards every user session note whose key starts with a configured
  prefix as a token claim. Designed for dynamic claim namespaces
  (e.g. `tz.idp.*`) where pre-authoring a mapper per claim is
  impractical. Opt-in `json.decode` flag parses session-note values as
  JSON so lists come out as real arrays on the token; falls back to a
  raw-string claim when a value isn't valid JSON, so mixing encoded and
  unencoded notes under one prefix is safe.
- **Prefixed attributes** (`oidc-prefixed-attribute-mapper`) —
  forwards every persisted user attribute whose key starts with a
  configured prefix as a token claim. Same prefix/strip/`json.decode`
  semantics as the session-note variant, but reads attributes off the
  user at token-mint time — so the claims also appear on tokens minted
  outside the broker flow (impersonation, direct grant, RFC 7523 JWT
  authorization grant). Single-valued attributes emit scalar claims;
  multi-valued attributes emit arrays.

### Authenticators

- **Set CUID attribute** — assigns a [CUID](https://github.com/paralleldrive/cuid2)
  to a user attribute during authentication.
- **Verify email from trusted broker** (`idp-trust-email-verifier`) — a
  first-broker-login step that marks a user's email verified when the identity
  provider trusts email and asserts an email matching the account. Keycloak's
  built-in `trustEmail` only verifies emails on *newly-created* broker users;
  this also covers pre-existing accounts (e.g. roster-provisioned users) that
  are later linked to the provider and would otherwise stay unverified. It
  never un-verifies an email and only acts when the asserted email matches the
  account's own email. The `always.trust` option skips the `trustEmail` check
  (the email-match requirement still applies) for flows where a preceding
  condition — e.g. `idp-asserted-domain-matches` — already establishes the
  provider's authority.
- **Condition - IdP asserted domain matches** (`idp-asserted-domain-matches`) —
  conditional for first-broker-login flows: true iff the email asserted by
  the external identity provider belongs to one of that provider's own
  configured domains (default: the `home.idp.discovery.domains` config
  attribute, `##`-delimited). Gate silent create/link executions
  (`idp-create-user-if-unique` / `idp-auto-link`) behind it and route
  out-of-domain assertions to Keycloak's confirm-link + email-verification
  path, so a provider can only silently bind accounts in domains it is
  authoritative for. Fails closed — missing broker context, absent email,
  or an empty domain list evaluate false; a `negate` option supports the
  else-branch subflow.

### Admin REST extensions

- **`GET /admin/realms/{realm}/users-by-attribute`** — paginated, filtered
  user lookup with group-membership and attribute predicates richer than
  the stock admin API exposes.
- **`GET /admin/realms/{realm}/credential-action-link`** — generate a
  one-time action-token URL (e.g. `UPDATE_PASSWORD`) for a user without
  sending Keycloak's built-in email. Returns the link, expiry, and token
  JTI so the caller can render its own branded email and audit the send.

## Compatibility

Known to be compatible with Keycloak 26. Tested most recently against
26.6.4; check `keycloak.version` in `pom.xml` for the exact target.

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
