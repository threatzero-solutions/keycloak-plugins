package org.threatzero.keycloak.plugins.mappers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.keycloak.Config.Scope;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Broker-time mapper that copies a SAML attribute value onto a <em>persisted
 * user attribute</em> during brokered login. The attribute-based sibling of
 * {@link SamlAttributeToSessionNoteMapper} and the SAML counterpart of
 * {@link OidcClaimToAttributeMapper}: because the value is persisted rather
 * than session-scoped, downstream protocol mappers (pair with
 * {@code oidc-prefixed-attribute-mapper}) can emit it on tokens minted
 * through any path — including impersonation and direct-grant/password
 * fallback, which never replay the broker pipeline.
 *
 * <p>Unlike Keycloak's built-in SAML attribute importer, this mapper carries
 * the session-note pair's {@code json.encode} semantics so multi-valued SAML
 * attributes round-trip as structured JSON, and it <em>clears</em> the
 * attribute when the assertion no longer carries the attribute (see below).
 *
 * <h3>Configuration</h3>
 *
 * <ul>
 *   <li>{@code attribute.name} (required): attribute name on the SAML
 *       assertion. Matched against either the attribute's {@code Name} or
 *       {@code FriendlyName}, matching the precedent set by
 *       {@link SamlAdvancedAttributeMapper}.
 *   <li>{@code user.attribute} (required): user attribute to write the value
 *       to. Always written single-valued; enable {@code json.encode} to carry
 *       multi-valued SAML attributes losslessly.
 *   <li>{@code json.encode} (default {@code false}): JSON-serialize the full
 *       value list before writing, preserving multi-valued attributes as an
 *       array. When false, only the first value is stored (legacy
 *       single-value behavior).
 * </ul>
 *
 * <h3>Clear-on-absent (differs from the session-note mapper)</h3>
 *
 * <p>When the assertion carries no values for the attribute, the user
 * attribute is <em>removed</em>, not left alone. A persisted attribute would
 * otherwise keep a prior login's value at rest and misrepresent the IDP's
 * current truth. Use sync mode FORCE so this update runs on every login.
 *
 * <h3>Realm prerequisite</h3>
 *
 * <p>With Keycloak's declarative user profile, writes to an undeclared
 * (unmanaged) attribute are silently dropped at commit. The realm must either
 * declare the target attribute or set
 * {@code unmanagedAttributePolicy=ADMIN_EDIT} (never {@code ENABLED} for
 * authorization-relevant attributes).
 */
public class SamlAttributeToAttributeMapper extends AbstractIdentityProviderMapper {

  private static final String ID = "saml-attribute-to-attribute-idp-mapper";

  private static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

  private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
      new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

  static final String ATTRIBUTE_NAME = "attribute.name";
  static final String USER_ATTRIBUTE = "user.attribute";
  static final String JSON_ENCODE = "json.encode";

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  static {
    ProviderConfigProperty attribute = new ProviderConfigProperty();
    attribute.setName(ATTRIBUTE_NAME);
    attribute.setLabel("Attribute");
    attribute.setType(ProviderConfigProperty.STRING_TYPE);
    attribute.setHelpText(
        "Name of the SAML attribute to copy. Matched against either the"
            + " attribute's Name or FriendlyName.");
    attribute.setRequired(true);
    configProperties.add(attribute);

    ProviderConfigProperty userAttribute = new ProviderConfigProperty();
    userAttribute.setName(USER_ATTRIBUTE);
    userAttribute.setLabel("User Attribute Name");
    userAttribute.setType(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE);
    userAttribute.setHelpText(
        "User attribute to write the value to. When the assertion carries no"
            + " values for the attribute, the user attribute is removed, so"
            + " with sync mode FORCE it tracks the identity provider's current"
            + " truth on every login. Downstream protocol mappers (e.g."
            + " oidc-prefixed-attribute-mapper) can project the attribute onto"
            + " issued tokens.");
    userAttribute.setRequired(true);
    configProperties.add(userAttribute);

    ProviderConfigProperty jsonEncode = new ProviderConfigProperty();
    jsonEncode.setName(JSON_ENCODE);
    jsonEncode.setLabel("JSON-Encode Value");
    jsonEncode.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    jsonEncode.setHelpText(
        "When true, the attribute's values are JSON-serialized before being"
            + " written to the user attribute, preserving multi-valued SAML"
            + " attributes as an array. Pair with a decoding protocol mapper"
            + " (e.g. oidc-prefixed-attribute-mapper with json.decode enabled)"
            + " to emit the claim as a structured JSON array on the issued"
            + " token. When false (default), only the first value is stored"
            + " via String.valueOf — legacy single-value behavior.");
    jsonEncode.setDefaultValue("false");
    jsonEncode.setRequired(false);
    configProperties.add(jsonEncode);
  }

  @Override
  public void close() {}

  @Override
  public SamlAttributeToAttributeMapper create(KeycloakSession session) {
    return new SamlAttributeToAttributeMapper();
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
    return "Copies a SAML attribute value from the brokered assertion onto a"
        + " persisted user attribute with no match conditions, removing the"
        + " attribute when the assertion no longer carries it. Pairs with the"
        + " 'Prefixed attributes' protocol mapper to forward claims onto"
        + " downstream tokens — including tokens minted outside the broker"
        + " flow (impersonation, direct grant).";
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
    return "Attribute to Attribute";
  }

  @Override
  public void importNewUser(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    apply(user, mapperModel, context);
  }

  @Override
  public void updateBrokeredUser(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    apply(user, mapperModel, context);
  }

  private void apply(
      UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
    String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
    String userAttribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
    if (attributeName == null
        || attributeName.isEmpty()
        || userAttribute == null
        || userAttribute.isEmpty()) {
      return;
    }

    List<Object> values = extractValues(context, attributeName);
    boolean jsonEncode = Boolean.parseBoolean(mapperModel.getConfig().get(JSON_ENCODE));
    // With JSON encoding off we preserve the legacy single-value behavior;
    // with it on, we serialize the full list so the protocol mapper can emit
    // it as a real JSON array. An empty list means the assertion no longer
    // carries the attribute → clear-on-absent.
    Object valueToEncode = values.isEmpty() ? null : (jsonEncode ? values : values.get(0));
    Optional<String> write = AttributeMapperHelper.resolveWrite(valueToEncode, jsonEncode);
    if (write.isPresent()) {
      user.setSingleAttribute(userAttribute, write.get());
    } else {
      user.removeAttribute(userAttribute);
    }
  }

  /** Collects every value of the named attribute across all assertion attribute statements. */
  private static List<Object> extractValues(BrokeredIdentityContext context, String attributeName) {
    AssertionType assertion =
        (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
    if (assertion == null) {
      return List.of();
    }
    Set<AttributeStatementType> statements = assertion.getAttributeStatements();
    if (statements == null) {
      return List.of();
    }
    return statements.stream()
        .flatMap(s -> s.getAttributes().stream())
        .filter(
            choice ->
                attributeName.equals(choice.getAttribute().getName())
                    || attributeName.equals(choice.getAttribute().getFriendlyName()))
        .flatMap(choice -> choice.getAttribute().getAttributeValue().stream())
        .toList();
  }
}
