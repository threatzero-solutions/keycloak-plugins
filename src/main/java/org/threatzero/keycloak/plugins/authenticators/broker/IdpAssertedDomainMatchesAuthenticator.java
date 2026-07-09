package org.threatzero.keycloak.plugins.authenticators.broker;

import java.util.Map;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Condition for first-broker-login flows: true iff the email asserted by the
 * external identity provider belongs to one of that provider's own configured
 * domains (by default the {@code home.idp.discovery.domains} config attribute
 * used by the home-IDP-discovery routing plugin).
 *
 * <p>Rationale: an identity provider is authoritative only for the domains
 * its operator has verified. Gate silent account creation/linking
 * ({@code idp-create-user-if-unique} / {@code idp-auto-link}) behind this
 * condition and route everything else to Keycloak's interactive
 * confirm-link/email-verification path, so an IDP asserting an email outside
 * its own domains cannot silently bind to (or pre-create) another domain's
 * account.
 *
 * <p>Evaluates against the brokered identity serialized into the
 * authentication session (the same note {@link AbstractIdpAuthenticator}
 * reads), so it only makes sense inside a first-broker-login flow. Fails
 * closed: missing broker context, unresolvable IDP, absent email, or an
 * empty domain list all evaluate to false (before negation), pushing the
 * login toward real ownership verification.
 */
public class IdpAssertedDomainMatchesAuthenticator implements ConditionalAuthenticator {

  static final IdpAssertedDomainMatchesAuthenticator SINGLETON =
      new IdpAssertedDomainMatchesAuthenticator();

  private static final Logger logger =
      Logger.getLogger(IdpAssertedDomainMatchesAuthenticator.class);

  @Override
  public boolean matchCondition(AuthenticationFlowContext context) {
    Map<String, String> config = configOf(context);
    boolean negate =
        Boolean.parseBoolean(
            config.getOrDefault(IdpAssertedDomainMatchesAuthenticatorFactory.NEGATE_CONFIG, "false"));
    return negate ^ assertedDomainMatches(context, config);
  }

  private boolean assertedDomainMatches(
      AuthenticationFlowContext context, Map<String, String> config) {
    SerializedBrokeredIdentityContext brokerCtx =
        SerializedBrokeredIdentityContext.readFromAuthenticationSession(
            context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
    if (brokerCtx == null) {
      logger.warn(
          "No brokered identity context in the authentication session; is this condition used"
              + " outside a first-broker-login flow?");
      return false;
    }

    String idpAlias = brokerCtx.getIdentityProviderId();
    IdentityProviderModel idp = context.getSession().identityProviders().getByAlias(idpAlias);
    if (idp == null) {
      logger.warnf("Identity provider '%s' from the brokered context not found.", idpAlias);
      return false;
    }

    String domainsAttribute =
        config.getOrDefault(
            IdpAssertedDomainMatchesAuthenticatorFactory.DOMAINS_ATTRIBUTE_CONFIG,
            IdpAssertedDomainMatchesAuthenticatorFactory.DOMAINS_ATTRIBUTE_DEFAULT);
    String delimiter =
        config.getOrDefault(
            IdpAssertedDomainMatchesAuthenticatorFactory.DOMAINS_DELIMITER_CONFIG,
            IdpAssertedDomainMatchesAuthenticatorFactory.DOMAINS_DELIMITER_DEFAULT);

    Map<String, String> idpConfig = idp.getConfig();
    String rawDomains = idpConfig == null ? null : idpConfig.get(domainsAttribute);
    Set<String> domains = EmailDomainMatcher.parseDomains(rawDomains, delimiter);
    boolean matches = EmailDomainMatcher.matches(brokerCtx.getEmail(), domains);

    logger.debugf(
        "Asserted email domain %s the domains configured on identity provider '%s'.",
        matches ? "matches" : "does not match", idpAlias);
    return matches;
  }

  private static Map<String, String> configOf(AuthenticationFlowContext context) {
    AuthenticatorConfigModel model = context.getAuthenticatorConfig();
    return model == null || model.getConfig() == null ? Map.of() : model.getConfig();
  }

  @Override
  public void action(AuthenticationFlowContext context) {}

  @Override
  public boolean requiresUser() {
    // Runs before any local user exists (first broker login may create one).
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}
}
