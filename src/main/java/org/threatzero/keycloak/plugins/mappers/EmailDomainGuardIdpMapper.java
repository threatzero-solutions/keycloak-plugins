package org.threatzero.keycloak.plugins.mappers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.threatzero.keycloak.plugins.authenticators.broker.EmailDomainMatcher;

/**
 * Broker-time guard that stops an already-linked identity provider from
 * rewriting an account's email onto a domain the provider is not authoritative
 * for. Companion to the {@code idp-asserted-domain-matches} first-broker-login
 * condition: that condition guards the create/link path, this mapper guards the
 * <em>update</em> path, which no authentication flow runs on.
 *
 * <h3>Why a mapper, and why preprocess</h3>
 *
 * <p>A returning brokered login (an existing {@code (idp, brokerUserId)}
 * federated link) skips first-broker-login entirely — Keycloak calls
 * {@code updateBrokeredUser} and, under sync mode FORCE, rewrites the account's
 * email and re-derives {@code emailVerified} from the provider's {@code
 * trustEmail}. There is no flow, so a flow authenticator can't see it. This
 * mapper's {@link #preprocessFederatedIdentity} runs in {@code
 * IdentityBrokerService.authenticated} <em>before</em> that write, so it can
 * suppress an out-of-domain email before it ever touches the account. Nulling
 * the context email is a safe no-op: Keycloak's {@code updateEmail}
 * early-returns on a null asserted email, leaving the account's existing
 * (legitimately verified) email untouched.
 *
 * <h3>Scope</h3>
 *
 * <ul>
 *   <li><b>Update path only.</b> Enforces only when a federated link already
 *       exists for this provider + broker user. First broker login is left to
 *       the domain-gated auth flow, so this mapper never changes create/link
 *       behavior.
 *   <li><b>Domains-present only.</b> If the provider has no configured domains,
 *       there is no basis to call an email out-of-domain, so the mapper passes
 *       through — a provider with unverified domains gets no update-path
 *       protection (configure domains to enable it), rather than having all its
 *       logins broken.
 * </ul>
 *
 * <p>Runs on all providers (OIDC and SAML) — it reads the normalized {@code
 * context.getEmail()} and the provider's domain list, neither of which is
 * protocol-specific.
 *
 * <h3>Configuration</h3>
 *
 * <ul>
 *   <li>{@code domains.attribute} (default {@code home.idp.discovery.domains}):
 *       the identity-provider config attribute holding the delimited list of
 *       domains the provider is authoritative for.
 *   <li>{@code domains.delimiter} (default {@code ##}): the literal separator
 *       between entries in that list.
 * </ul>
 */
public class EmailDomainGuardIdpMapper extends AbstractIdentityProviderMapper {

  private static final String ID = "email-domain-guard-idp-mapper";

  private static final String[] COMPATIBLE_PROVIDERS = {IdentityProviderMapper.ANY_PROVIDER};

  private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
      new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

  private static final Logger logger = Logger.getLogger(EmailDomainGuardIdpMapper.class);

  static final String DOMAINS_ATTRIBUTE_CONFIG = "domains.attribute";
  static final String DOMAINS_ATTRIBUTE_DEFAULT = "home.idp.discovery.domains";
  static final String DOMAINS_DELIMITER_CONFIG = "domains.delimiter";
  static final String DOMAINS_DELIMITER_DEFAULT = "##";

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  static {
    ProviderConfigProperty attribute = new ProviderConfigProperty();
    attribute.setName(DOMAINS_ATTRIBUTE_CONFIG);
    attribute.setLabel("Domains Attribute");
    attribute.setType(ProviderConfigProperty.STRING_TYPE);
    attribute.setHelpText(
        "The identity provider config attribute holding the delimited list of domains the"
            + " provider is authoritative for.");
    attribute.setDefaultValue(DOMAINS_ATTRIBUTE_DEFAULT);
    configProperties.add(attribute);

    ProviderConfigProperty delimiter = new ProviderConfigProperty();
    delimiter.setName(DOMAINS_DELIMITER_CONFIG);
    delimiter.setLabel("Domains Delimiter");
    delimiter.setType(ProviderConfigProperty.STRING_TYPE);
    delimiter.setHelpText("The literal separator between entries in the domain list.");
    delimiter.setDefaultValue(DOMAINS_DELIMITER_DEFAULT);
    configProperties.add(delimiter);
  }

  @Override
  public void close() {}

  @Override
  public EmailDomainGuardIdpMapper create(KeycloakSession session) {
    return new EmailDomainGuardIdpMapper();
  }

  @Override
  public void init(Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public String getHelpText() {
    return "On a returning brokered login (existing link), suppresses an email the identity"
        + " provider asserts for a domain it is not authoritative for, so the provider cannot move"
        + " an already-linked account onto a domain it does not own. First broker login is handled"
        + " by the auth flow, not this mapper.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
    return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
  }

  @Override
  public String[] getCompatibleProviders() {
    return COMPATIBLE_PROVIDERS;
  }

  @Override
  public String getDisplayCategory() {
    return "Attribute Importer";
  }

  @Override
  public String getDisplayType() {
    return "Email Domain Guard";
  }

  @Override
  public void preprocessFederatedIdentity(
      KeycloakSession session,
      RealmModel realm,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    String email = context.getEmail();
    IdentityProviderModel idp = context.getIdpConfig();
    if (email == null || email.isBlank() || idp == null) {
      return;
    }

    String alias = idp.getAlias();
    String brokerUserId = context.getBrokerUserId();
    if (alias == null || brokerUserId == null) {
      return;
    }

    // Enforce only on the update path: a link for this (provider, broker user)
    // must already exist. On first broker login none exists yet — that path is
    // the auth flow's job, so leave the context untouched here.
    boolean hasExistingLink =
        session
                .users()
                .getUserByFederatedIdentity(
                    realm, new FederatedIdentityModel(alias, brokerUserId, context.getUsername()))
            != null;

    Map<String, String> idpConfig = idp.getConfig();
    String attribute = configValue(mapperModel, DOMAINS_ATTRIBUTE_CONFIG, DOMAINS_ATTRIBUTE_DEFAULT);
    String delimiter = configValue(mapperModel, DOMAINS_DELIMITER_CONFIG, DOMAINS_DELIMITER_DEFAULT);
    Set<String> domains =
        EmailDomainMatcher.parseDomains(
            idpConfig == null ? null : idpConfig.get(attribute), delimiter);

    if (shouldSuppressEmail(email, domains, hasExistingLink)) {
      // Null asserted email → Keycloak's updateEmail is a no-op → the account
      // keeps its current verified email. This refuses the out-of-domain
      // rewrite without failing the login or clearing the stored address.
      logger.warnf(
          "Blocked out-of-domain email update via identity provider '%s': asserted email domain is"
              + " not among the provider's authoritative domains. Keeping the account's existing"
              + " email.",
          alias);
      context.setEmail(null);
    }
  }

  /**
   * Whether the asserted email must be suppressed on the update path.
   *
   * @param email the email the provider asserts this login (already known non-blank by the caller)
   * @param domains the provider's normalized authoritative-domain set
   * @param hasExistingLink whether a federated link already exists (i.e. this is the update path)
   * @return true iff this is the update path, domains are configured, and the email is out-of-domain
   */
  static boolean shouldSuppressEmail(String email, Set<String> domains, boolean hasExistingLink) {
    if (!hasExistingLink || domains == null || domains.isEmpty()) {
      return false;
    }
    return !EmailDomainMatcher.matches(email, domains);
  }

  private static String configValue(
      IdentityProviderMapperModel mapperModel, String key, String fallback) {
    Map<String, String> config = mapperModel.getConfig();
    if (config == null) {
      return fallback;
    }
    String value = config.get(key);
    return value == null || value.isEmpty() ? fallback : value;
  }
}
