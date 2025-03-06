package org.threatzero.keycloak.plugins.authenticators.user;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class SetCuidAttributeAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "set-cuid-attribute-authenticator";

  public static final String ATTRIBUTE_NAME_CONFIG = "cuid.attribute.name";
  public static final String OVERWRITE_ON_LOGIN_CONFIG = "cuid.overwrite.on.login";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new SetCuidAttributeAuthenticator();
  }

  @Override
  public String getReferenceCategory() {
    return "userAttributes";
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
    return "Set CUID Attribute";
  }

  @Override
  public String getHelpText() {
    return "This authenticator sets a CUID attribute to the user.";
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
    property.setName(ATTRIBUTE_NAME_CONFIG);
    property.setLabel("Attribute Name");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the attribute to set the CUID to.");
    property.setDefaultValue("cuid");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(OVERWRITE_ON_LOGIN_CONFIG);
    property.setLabel("Overwrite on Login");
    property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    property.setHelpText(
        "If this option is true, the CUID attribute will be overwritten on each login.");
    property.setDefaultValue(false);
    configProperties.add(property);
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }
}
