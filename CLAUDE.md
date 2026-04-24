# CLAUDE.md

## What is this

Custom Keycloak plugins — IDP mappers, authenticators, admin resources, and
protocol mappers — packaged as a single shaded JAR. Originally developed for
the ThreatZero platform but published open source under MIT.

This repo is public. Hold the bar accordingly: code quality, tests, and
docs should be good enough to hand to an outside Keycloak operator and have
them understand what's here without reading every class.

## Tech stack

- Java 21 (source + target)
- Maven (no wrapper — use a system `mvn`)
- Keycloak 26.3.3 SPIs (`provided` scope)
- Lombok
- JUnit 5 (Jupiter)
- Shaded into a single fat JAR via `maven-shade-plugin`, with
  `ServicesResourceTransformer` so the `META-INF/services/*` entries merge
  across artifacts.

## Build, test, release

```bash
mvn clean install            # compile, run tests, produce shaded JAR
mvn test                     # unit tests only
mvn package                  # JAR without running install
```

The shaded artifact lands at `target/keycloak-plugins-<version>.jar` and is
what downstream Keycloak images consume.

**Release flow** — `/.github/workflows/release-package.yml` runs on push to
`main`: it builds, reads the version from `pom.xml`, and creates a GitHub
release tagged with that version carrying the JAR as an artifact. To ship a
new release, bump `<version>` in `pom.xml`, commit, and merge to main. The
workflow will refuse to re-release an existing tag, so every merge to main
must be paired with a version bump when there are publishable changes.

## Repo layout

```
src/main/java/org/threatzero/keycloak/plugins/
  mappers/          IDP and protocol mappers
  authenticators/   custom authentication flows
  services/         admin REST extensions + shared models
src/main/resources/META-INF/services/
  <spi-name>        one line per implementation class, per SPI
src/test/java/...   JUnit tests mirroring the main package tree
```

## Keycloak SPI registration

Every plugin must be registered in `META-INF/services/<spi-interface>`:

- `org.keycloak.broker.provider.IdentityProviderMapper` — broker-time mappers
  that run while a user is being provisioned from an external IDP.
- `org.keycloak.protocol.ProtocolMapper` — token-mint-time mappers that run
  when Keycloak issues an access/ID/userinfo token.
- `org.keycloak.authentication.AuthenticatorFactory` — custom steps for
  authentication flows.
- `org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory`
  — additional endpoints under `/admin/realms/{realm}/<provider-id>`.

When adding a new SPI that isn't already used in the repo, create the
services file alongside the existing ones and append one line per class.
Forgetting this file is the #1 way to have Keycloak silently ignore a
working implementation.

## Conventions

- **Package:** `org.threatzero.keycloak.plugins.<category>` (mappers,
  authenticators, services).
- **Class naming:** descriptive and protocol-aware —
  `OidcAdvancedAttributeMapper`, `SamlAdvancedAttributeMapper`. Don't
  abbreviate "OIDC" / "SAML" away.
- **Provider IDs:** dashed, lowercase, and match the Keycloak built-in
  naming style (`oidc-advanced-attribute-idp-mapper`, not
  `OidcAdvancedAttributeMapper`). The ID is what appears in exported realm
  JSON and is effectively a public API — changing it breaks existing
  Keycloak configurations.
- **Config property keys:** dotted lowercase (`user.attribute`,
  `note.prefix`), matching Keycloak conventions so the admin UI renders
  consistently.
- **Tests:** co-locate under `src/test/java/...` mirroring the main tree.
  Pure-Java helpers are easy to unit-test; SPI classes that need a
  `KeycloakSession` generally aren't worth mocking — extract the logic into
  a testable helper and unit-test that.
- **Docs:** each plugin should have a class-level Javadoc that answers
  "what does this do, when does Keycloak call it, and what config does it
  take." A reader should understand the plugin without running it.

## Adding a new plugin

1. Pick the SPI (IDP mapper? protocol mapper? authenticator?).
2. Write the class in the matching sub-package. Extend the appropriate
   abstract base (`AbstractClaimMapper`, `AbstractIdentityProviderMapper`,
   `AbstractOIDCProtocolMapper`, etc.).
3. Define config properties as a static `List<ProviderConfigProperty>`
   populated in a `static {}` block — this is the repo's existing pattern
   and matches Keycloak's own built-ins.
4. Register the fully-qualified class name in the matching
   `META-INF/services/<spi>` file.
5. Extract any non-trivial logic to a pure helper and test it under
   `src/test/java`.
6. Update `README.md` with a one-line description of the plugin.
7. Bump `pom.xml` version (semver: breaking = major, new plugin = minor,
   fix-only = patch).

## Compatibility

Keycloak SPIs are not stable across major versions. When Keycloak bumps
(e.g., 26 → 27), expect at minimum a `keycloak.version` pom update and
sometimes method-signature churn. Verify with `mvn clean install` and a
quick smoke test in the target Keycloak version's admin UI.
