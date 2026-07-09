package org.threatzero.keycloak.plugins.authenticators.broker;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * First-broker-login authenticator that marks a user's email as verified when they authenticate
 * through an identity provider configured to trust email ({@code trustEmail=true}).
 *
 * <p>Keycloak's built-in {@code trustEmail} only marks the email verified when the broker <em>creates</em>
 * a brand-new user. A user who already exists (e.g. provisioned from a roster) and is then linked to the
 * IdP keeps their original {@code emailVerified=false}, which silently blocks downstream logic that gates on
 * a verified email. This authenticator closes that gap: on first-broker-login it verifies the email for both
 * newly-created and newly-linked accounts.
 *
 * <p>Trust boundary: it verifies only when the IdP asserts an email that matches the account's own email
 * (case-insensitive). If the account was matched on something other than email, or the IdP asserted no email,
 * nothing is changed. It never un-verifies an email.
 *
 * <p>The {@code always.trust} config option skips the {@code trustEmail} check (the email-match
 * requirement still applies). Use it only where a preceding flow condition has already established
 * the provider's authority over the asserted email — e.g. behind {@code
 * idp-asserted-domain-matches} in a domain-gated first-broker-login flow, where {@code trustEmail}
 * is deliberately left off so Keycloak's own verification path stays live for the ungated branch.
 */
public class IdpTrustEmailVerifierAuthenticator implements Authenticator {
  private static final Logger LOG = Logger.getLogger(IdpTrustEmailVerifierAuthenticator.class);

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();

    // Nothing to do if the account isn't established yet or the email is already verified.
    if (user == null || user.isEmailVerified()) {
      context.success();
      return;
    }

    SerializedBrokeredIdentityContext serializedCtx =
        SerializedBrokeredIdentityContext.readFromAuthenticationSession(
            context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

    // Not a broker login (defensive — this authenticator is only bound to first-broker-login flows).
    if (serializedCtx == null) {
      context.success();
      return;
    }

    BrokeredIdentityContext brokerContext =
        serializedCtx.deserialize(context.getSession(), context.getAuthenticationSession());
    IdentityProviderModel idpConfig = brokerContext.getIdpConfig();

    AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
    boolean alwaysTrust =
        authConfig != null
            && authConfig.getConfig() != null
            && Boolean.parseBoolean(
                authConfig
                    .getConfig()
                    .get(IdpTrustEmailVerifierAuthenticatorFactory.ALWAYS_TRUST_CONFIG));

    if (idpConfig != null
        && shouldVerifyEmail(
            idpConfig.isTrustEmail(), alwaysTrust, brokerContext.getEmail(), user.getEmail())) {
      user.setEmailVerified(true);
      LOG.infof(
          "Marked email verified for user %s via trusted IdP %s",
          user.getUsername(), idpConfig.getAlias());
    }

    context.success();
  }

  /**
   * Whether a trusted-broker login should mark the account's email verified.
   *
   * @param trustEmail the IdP's {@code trustEmail} flag (nullable, as Keycloak returns it)
   * @param alwaysTrust the execution's {@code always.trust} config — treat the broker as trusted
   *     regardless of {@code trustEmail} (a preceding flow condition vouches for it)
   * @param brokeredEmail the email asserted by the IdP for this login
   * @param userEmail the email on the matched/created account
   * @return true only when the broker is trusted (either flag) and asserts a non-blank email that
   *     matches the account's own email (case-insensitive)
   */
  static boolean shouldVerifyEmail(
      Boolean trustEmail, boolean alwaysTrust, String brokeredEmail, String userEmail) {
    return (alwaysTrust || Boolean.TRUE.equals(trustEmail))
        && brokeredEmail != null
        && !brokeredEmail.isBlank()
        && brokeredEmail.equalsIgnoreCase(userEmail);
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    authenticate(context);
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }
}
