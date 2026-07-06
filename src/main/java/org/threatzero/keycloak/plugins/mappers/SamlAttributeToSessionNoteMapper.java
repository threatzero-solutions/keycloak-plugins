package org.threatzero.keycloak.plugins.mappers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
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
 * Broker-time mapper that copies a SAML attribute value onto a user session
 * note during brokered login. Fills the gap in stock Keycloak 26, which ships
 * an OIDC-only session-note IDP mapper and no SAML equivalent, forcing SAML
 * brokers to route claims through user attributes.
 *
 * <h3>Configuration</h3>
 *
 * <ul>
 *   <li>{@code attribute.name} (required): attribute name on the SAML
 *       assertion. Matched against either the attribute's {@code Name} or
 *       {@code FriendlyName}, matching the precedent set by
 *       {@link SamlAdvancedAttributeMapper}.
 *   <li>{@code user.session.note} (required): session-note key to write the
 *       attribute value under.
 * </ul>
 *
 * <p>If the attribute has multiple values on the assertion, only the first is
 * written. Empty or missing attributes leave the session note unset. Pairs
 * with {@code PrefixedSessionNoteMapper} (or Keycloak's built-in User Session
 * Note protocol mapper) to forward the note onto downstream tokens.
 */
public class SamlAttributeToSessionNoteMapper extends AbstractIdentityProviderMapper {

  private static final String ID = "saml-attribute-to-session-note-idp-mapper";

  private static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

  private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
      new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

  static final String ATTRIBUTE_NAME = "attribute.name";
  static final String NOTE_KEY = "user.session.note";
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

    ProviderConfigProperty noteKey = new ProviderConfigProperty();
    noteKey.setName(NOTE_KEY);
    noteKey.setLabel("User Session Note");
    noteKey.setType(ProviderConfigProperty.STRING_TYPE);
    noteKey.setHelpText(
        "Key under which the attribute value is stored on the user session"
            + " note. Downstream protocol mappers can project the note onto"
            + " issued tokens.");
    noteKey.setRequired(true);
    configProperties.add(noteKey);

    ProviderConfigProperty jsonEncode = new ProviderConfigProperty();
    jsonEncode.setName(JSON_ENCODE);
    jsonEncode.setLabel("JSON-Encode Value");
    jsonEncode.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    jsonEncode.setHelpText(
        "When true, the attribute's values are JSON-serialized before being"
            + " written to the session note, preserving multi-valued SAML"
            + " attributes as an array. Pair with a decoding protocol mapper"
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
  public SamlAttributeToSessionNoteMapper create(KeycloakSession session) {
    return new SamlAttributeToSessionNoteMapper();
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
        + " user session note with no match conditions. Fills the gap left by"
        + " stock Keycloak, which only ships a session-note IDP mapper for OIDC.";
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
    return "Attribute to User Session Note";
  }

  @Override
  public void importNewUser(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    apply(mapperModel, context);
  }

  @Override
  public void updateBrokeredUser(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    apply(mapperModel, context);
  }

  private void apply(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
    String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
    String noteKey = mapperModel.getConfig().get(NOTE_KEY);
    if (attributeName == null
        || attributeName.isEmpty()
        || noteKey == null
        || noteKey.isEmpty()) {
      return;
    }

    AssertionType assertion =
        (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
    if (assertion == null) {
      return;
    }
    Set<AttributeStatementType> statements = assertion.getAttributeStatements();
    if (statements == null) {
      return;
    }

    List<Object> values =
        statements.stream()
            .flatMap(s -> s.getAttributes().stream())
            .filter(
                choice ->
                    attributeName.equals(choice.getAttribute().getName())
                        || attributeName.equals(choice.getAttribute().getFriendlyName()))
            .flatMap(choice -> choice.getAttribute().getAttributeValue().stream())
            .toList();

    if (values.isEmpty()) {
      return;
    }

    boolean jsonEncode = Boolean.parseBoolean(mapperModel.getConfig().get(JSON_ENCODE));
    // With JSON encoding off we preserve the legacy single-value behavior —
    // session notes can only hold a string and the downstream code path
    // predated structured support. With it on, we serialize the full list
    // so the protocol mapper can emit it as a real JSON array.
    Object valueToEncode = jsonEncode ? values : values.get(0);
    context.setSessionNote(noteKey, ClaimJsonCodec.encode(valueToEncode, jsonEncode));
  }
}
