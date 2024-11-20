package org.threatzero.keycloak.plugins.mappers;

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

  private static final String MATCH_PATTERNS = "patterns";
  private static final String DEFAULT_VALUE = "defaultValue";
  private static final String PATTERN_TYPE = "patternType";
  private static final String ATTRIBUTE_NAME = "attributeName";

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
    return List.of(
        new ProviderConfigProperty(
            CLAIM,
            "Claim",
            "The name of the claim to match against. You can reference nested claims using a '.',"
                + " i.e. 'address.locality'. To use dot (.) literally, escape it with backslash."
                + " (\\.)",
            ProviderConfigProperty.STRING_TYPE,
            ""),
        new ProviderConfigProperty(
            MATCH_PATTERNS,
            "Match Patterns",
            "The patterns and the corresponding values to assign to the attribute upon match. The"
                + " key should be a pattern of one of the types below and the value should be the"
                + " value that is assigned to the user attribute if the pattern matches.",
            ProviderConfigProperty.MAP_TYPE,
            Map.of()),
        new ProviderConfigProperty(
            DEFAULT_VALUE,
            "Default Value",
            "The value to use if no claims match.",
            ProviderConfigProperty.STRING_TYPE,
            ""),
        new ProviderConfigProperty(
            PATTERN_TYPE,
            "Pattern Type",
            "Algorithm used to match claims. Supported types: plain, regex, glob.",
            ProviderConfigProperty.LIST_TYPE,
            "plain",
            "plain",
            "regex",
            "glob"),
        new ProviderConfigProperty(
            ATTRIBUTE_NAME,
            "User Attribute Name",
            "User attribute to assign claim value to.",
            ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE,
            ""));
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
    String claimValue = String.valueOf(getClaimValue(mapperModel, context));

    String attributeValue = mapperModel.getConfig().get(DEFAULT_VALUE);

    for (Map.Entry<String, List<String>> matchPattern : matchPatterns.entrySet()) {
      if (valueMatches(matchPattern.getKey(), claimValue, patternType)) {
        attributeValue = matchPattern.getValue().get(0);
        break;
      }
    }

    String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
    if (attributeName != null) {
      user.setSingleAttribute(attributeName, attributeValue);
    }
  }
}
