package org.threatzero.keycloak.plugins.mappers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.keycloak.Config.Scope;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class OidcAdvancedAttributeMapper extends AbstractClaimMapper {
  private static final String ID = "oidc-advanced-attribute-mapper";

  private static final String[] COMPATIBLE_PROVIDERS = {
    KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID
  };
  private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
      new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  private static final String CLAIM_NAME = "attribute.name";
  private static final String MATCH_PATTERNS = "patterns";
  private static final String DEFAULT_VALUE = "default.value";
  private static final String PATTERN_TYPE = "pattern.type";
  private static final String ATTRIBUTE_NAME = "user.attribute";

  static {
    // CLAIM property
    ProviderConfigProperty claimProperty = new ProviderConfigProperty();
    claimProperty.setName(CLAIM_NAME);
    claimProperty.setLabel("Claim");
    claimProperty.setType(ProviderConfigProperty.STRING_TYPE);
    claimProperty.setHelpText(
        "The name of the claim to match against. You can reference nested claims using a '.',"
            + " i.e. 'address.locality'. To use dot (.) literally, escape it with backslash."
            + " (\\.)");
    configProperties.add(claimProperty);

    // MATCH_PATTERNS property
    ProviderConfigProperty matchPatternsProperty = new ProviderConfigProperty();
    matchPatternsProperty.setName(MATCH_PATTERNS);
    matchPatternsProperty.setLabel("Match Patterns");
    matchPatternsProperty.setType(ProviderConfigProperty.MAP_TYPE);
    matchPatternsProperty.setHelpText(
        "The patterns and the corresponding values to assign to the attribute upon match. The"
            + " key should be a pattern of one of the types below and the value should be the"
            + " value that is assigned to the user attribute if the pattern matches.");
    configProperties.add(matchPatternsProperty);

    // DEFAULT_VALUE property
    ProviderConfigProperty defaultValueProperty = new ProviderConfigProperty();
    defaultValueProperty.setName(DEFAULT_VALUE);
    defaultValueProperty.setLabel("Default Value");
    defaultValueProperty.setType(ProviderConfigProperty.STRING_TYPE);
    defaultValueProperty.setHelpText("The value to use if no claims match.");
    configProperties.add(defaultValueProperty);

    // PATTERN_TYPE property
    ProviderConfigProperty patternTypeProperty = new ProviderConfigProperty();
    patternTypeProperty.setName(PATTERN_TYPE);
    patternTypeProperty.setLabel("Pattern Type");
    patternTypeProperty.setType(ProviderConfigProperty.LIST_TYPE);
    patternTypeProperty.setHelpText(
        "Algorithm used to match claims. Supported types: exact, regex, glob.");
    patternTypeProperty.setOptions(List.of("exact", "regex", "glob"));
    patternTypeProperty.setDefaultValue("exact");
    configProperties.add(patternTypeProperty);

    // ATTRIBUTE_NAME property
    ProviderConfigProperty attributeNameProperty = new ProviderConfigProperty();
    attributeNameProperty.setName(ATTRIBUTE_NAME);
    attributeNameProperty.setLabel("User Attribute Name");
    attributeNameProperty.setType(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE);
    attributeNameProperty.setHelpText("The name of the user attribute to assign the value to.");
  }

  @Override
  public void close() {}

  @Override
  public OidcAdvancedAttributeMapper create(KeycloakSession session) {
    return new OidcAdvancedAttributeMapper();
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
    return "Dynamically match a claim using patterns to various attribute values.";
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
    return "Advanced Claim to Attribute";
  }

  @Override
  public void importNewUser(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    apply(session, realm, user, mapperModel, context);
  }

  @Override
  public void updateBrokeredUser(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    apply(session, realm, user, mapperModel, context);
  }

  protected boolean valueMatches(String pattern, String value, String patternType) {
    if (value != null) {
      switch (patternType) {
        case "plain":
          return pattern.equals(value);
        case "regex":
          return Pattern.compile(pattern).matcher((String) value).matches();
        case "glob":
          return MapperUtils.matchesGlob(pattern, value);
        default:
          return false;
      }
    }

    return false;
  }

  protected void apply(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    Map<String, List<String>> matchPatterns = mapperModel.getConfigMap(MATCH_PATTERNS);
    String patternType = mapperModel.getConfig().get(PATTERN_TYPE);
    String claimName = mapperModel.getConfig().get(CLAIM_NAME);
    String claimValue = String.valueOf(getClaimValue(context, claimName));

    String attributeValue = mapperModel.getConfig().get(DEFAULT_VALUE);

    for (Map.Entry<String, List<String>> matchPattern : matchPatterns.entrySet()) {
      if (valueMatches(matchPattern.getKey(), claimValue, patternType)) {
        attributeValue = matchPattern.getValue().get(0);
        break;
      }
    }

    String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
    if (attributeName != null && attributeValue != null && !attributeValue.isBlank()) {
      user.setSingleAttribute(attributeName, attributeValue);
    }
  }
}
