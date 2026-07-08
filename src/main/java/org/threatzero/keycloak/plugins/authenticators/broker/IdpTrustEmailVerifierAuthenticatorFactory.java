package org.threatzero.keycloak.plugins.authenticators.broker;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class IdpTrustEmailVerifierAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "idp-trust-email-verifier";

  private static final IdpTrustEmailVerifierAuthenticator SINGLETON =
      new IdpTrustEmailVerifierAuthenticator();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public String getReferenceCategory() {
    return "verifyEmail";
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.DISABLED,
    };
  }

  @Override
  public String getDisplayType() {
    return "Verify Email From Trusted Broker";
  }

  @Override
  public String getHelpText() {
    return "On first broker login, marks the user's email as verified when the identity provider trusts"
        + " email and asserts an email matching the account. Fixes users who existed before being linked"
        + " to the provider and would otherwise stay unverified.";
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }
}
