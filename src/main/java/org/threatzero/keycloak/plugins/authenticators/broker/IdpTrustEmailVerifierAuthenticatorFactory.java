package org.threatzero.keycloak.plugins.authenticators.broker;

import java.util.ArrayList;
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

  public static final String ALWAYS_TRUST_CONFIG = "always.trust";

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
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  private static final List<ProviderConfigProperty> configProperties =
      new ArrayList<ProviderConfigProperty>();

  static {
    ProviderConfigProperty property;
    property = new ProviderConfigProperty();
    property.setName(ALWAYS_TRUST_CONFIG);
    property.setLabel("Always Trust Email");
    property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    property.setHelpText(
        "Mark matching asserted emails verified even when the identity provider does not trust"
            + " email. Use only where a preceding flow condition already establishes the"
            + " provider's authority over the asserted email (e.g. Condition - IdP asserted"
            + " domain matches).");
    property.setDefaultValue(false);
    configProperties.add(property);
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }
}
