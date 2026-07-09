package org.threatzero.keycloak.plugins.authenticators.broker;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class IdpAssertedDomainMatchesAuthenticatorFactory
    implements ConditionalAuthenticatorFactory {
  public static final String PROVIDER_ID = "idp-asserted-domain-matches";

  public static final String DOMAINS_ATTRIBUTE_CONFIG = "domains.attribute";
  public static final String DOMAINS_ATTRIBUTE_DEFAULT = "home.idp.discovery.domains";
  public static final String DOMAINS_DELIMITER_CONFIG = "domains.delimiter";
  public static final String DOMAINS_DELIMITER_DEFAULT = "##";
  public static final String NEGATE_CONFIG = "negate";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public ConditionalAuthenticator getSingleton() {
    return IdpAssertedDomainMatchesAuthenticator.SINGLETON;
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
    return "Condition - IdP asserted domain matches";
  }

  @Override
  public String getHelpText() {
    return "Condition matches if the email asserted by the external identity provider belongs to"
        + " one of the domains configured on that identity provider. Use in a first-broker-login"
        + " flow to gate silent account creation/linking to the provider's own domains.";
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
    property.setName(DOMAINS_ATTRIBUTE_CONFIG);
    property.setLabel("Domains Attribute");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText(
        "The identity provider config attribute holding the delimited list of domains the"
            + " provider is authoritative for.");
    property.setDefaultValue(DOMAINS_ATTRIBUTE_DEFAULT);
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(DOMAINS_DELIMITER_CONFIG);
    property.setLabel("Domains Delimiter");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The literal separator between entries in the domain list.");
    property.setDefaultValue(DOMAINS_DELIMITER_DEFAULT);
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(NEGATE_CONFIG);
    property.setLabel("Negate output");
    property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    property.setHelpText(
        "Apply a NOT to the check result. Use for the else-branch subflow of a domain-gated"
            + " flow.");
    property.setDefaultValue(false);
    configProperties.add(property);
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }
}
