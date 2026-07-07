package org.threatzero.keycloak.plugins.mappers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

/**
 * Forwards every persisted user attribute whose key starts with a configured
 * prefix onto the access, ID, and/or UserInfo token as a claim of the same
 * name. The attribute-based sibling of {@link PrefixedSessionNoteMapper}.
 *
 * <p>Because it reads attributes off the {@code UserModel} at token-mint
 * time — not session notes — the claims survive every path that mints a
 * token for the user: brokered browser SSO, impersonation, direct-grant /
 * password fallback, and the RFC 7523 JWT Authorization Grant. It is
 * population-agnostic: attributes may be written by
 * {@code oidc-claim-to-attribute-idp-mapper} at broker time or by an
 * external provisioning system through the admin API.
 *
 * <h3>Configuration</h3>
 *
 * <ul>
 *   <li>{@code attribute.prefix} (required): user attributes whose key
 *       starts with this prefix are forwarded. Example: {@code tz.idp.}
 *   <li>{@code strip.prefix} (default {@code false}): when true, the prefix
 *       is removed from the emitted claim name. {@code tz.idp.department}
 *       becomes claim {@code department} on the token.
 *   <li>{@code json.decode} (default {@code false}): parse each attribute
 *       value as JSON before emitting; invalid JSON falls back to the raw
 *       string.
 *   <li>Standard OIDC flags ({@code access.token.claim},
 *       {@code id.token.claim}, {@code userinfo.token.claim}): control which
 *       tokens the claims are added to.
 * </ul>
 *
 * <h3>Value handling</h3>
 *
 * <p>Attribute values are string lists. A single-valued attribute is emitted
 * as a scalar claim; a multi-valued attribute is emitted as an array. With
 * {@code json.decode} enabled each value is parsed independently, so a
 * JSON-encoded single value comes out as its structured form. Attributes
 * with no values are skipped.
 *
 * <p>Note: {@code UserModel.getAttributes()} merges the built-in root
 * attributes ({@code username}, {@code email}, {@code firstName},
 * {@code lastName}) into the map — a namespaced prefix like {@code tz.idp.}
 * naturally excludes them, but an overly broad prefix would capture them
 * onto the token.
 */
public class PrefixedAttributeMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

  public static final String PROVIDER_ID = "oidc-prefixed-attribute-mapper";

  static final String ATTRIBUTE_PREFIX = "attribute.prefix";
  static final String STRIP_PREFIX = "strip.prefix";
  static final String JSON_DECODE = "json.decode";

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  static {
    ProviderConfigProperty prefix = new ProviderConfigProperty();
    prefix.setName(ATTRIBUTE_PREFIX);
    prefix.setLabel("Attribute Prefix");
    prefix.setType(ProviderConfigProperty.STRING_TYPE);
    prefix.setHelpText(
        "Every user attribute whose key starts with this prefix is forwarded"
            + " as a token claim. Example: 'tz.idp.' forwards attribute"
            + " 'tz.idp.department' as claim 'tz.idp.department' (or"
            + " 'department' if Strip Prefix is enabled).");
    prefix.setRequired(true);
    configProperties.add(prefix);

    ProviderConfigProperty strip = new ProviderConfigProperty();
    strip.setName(STRIP_PREFIX);
    strip.setLabel("Strip Prefix From Claim Name");
    strip.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    strip.setHelpText(
        "When true, the prefix is removed from the emitted claim name. Leave"
            + " disabled to preserve the full attribute key on the token.");
    strip.setDefaultValue("false");
    strip.setRequired(false);
    configProperties.add(strip);

    ProviderConfigProperty jsonDecode = new ProviderConfigProperty();
    jsonDecode.setName(JSON_DECODE);
    jsonDecode.setLabel("JSON-Decode Value");
    jsonDecode.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    jsonDecode.setHelpText(
        "When true, each matching attribute value is parsed as JSON before"
            + " being written to the token — lists come out as arrays, objects"
            + " as nested objects, typed scalars keep their type. Pair with"
            + " claim-to-attribute IDP mappers that have json.encode enabled"
            + " so structured claims round-trip losslessly. When a value isn't"
            + " valid JSON the decoder falls back to emitting the raw string,"
            + " so mixing encoded and unencoded attributes under one prefix is"
            + " safe. When false (default), values are emitted as strings.");
    jsonDecode.setDefaultValue("false");
    jsonDecode.setRequired(false);
    configProperties.add(jsonDecode);

    OIDCAttributeMapperHelper.addIncludeInTokensConfig(
        configProperties, PrefixedAttributeMapper.class);
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayCategory() {
    return "Token mapper";
  }

  @Override
  public String getDisplayType() {
    return "Prefixed attributes";
  }

  @Override
  public String getHelpText() {
    return "Forwards every user attribute whose key starts with a configured"
        + " prefix as a token claim. Reads persisted attributes rather than"
        + " session notes, so claims survive token paths that skip the broker"
        + " flow (impersonation, JWT authorization grant). Single-valued"
        + " attributes emit scalars; multi-valued attributes emit arrays.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public AccessToken transformAccessToken(
      AccessToken token,
      ProtocolMapperModel mapperModel,
      KeycloakSession session,
      UserSessionModel userSession,
      ClientSessionContext clientSessionCtx) {
    if (OIDCAttributeMapperHelper.includeInAccessToken(mapperModel)) {
      emit(token, mapperModel, userSession);
    }
    return token;
  }

  @Override
  public IDToken transformIDToken(
      IDToken token,
      ProtocolMapperModel mapperModel,
      KeycloakSession session,
      UserSessionModel userSession,
      ClientSessionContext clientSessionCtx) {
    if (OIDCAttributeMapperHelper.includeInIDToken(mapperModel)) {
      emit(token, mapperModel, userSession);
    }
    return token;
  }

  @Override
  public AccessToken transformUserInfoToken(
      AccessToken token,
      ProtocolMapperModel mapperModel,
      KeycloakSession session,
      UserSessionModel userSession,
      ClientSessionContext clientSessionCtx) {
    if (OIDCAttributeMapperHelper.includeInUserInfo(mapperModel)) {
      emit(token, mapperModel, userSession);
    }
    return token;
  }

  private static void emit(
      IDToken token, ProtocolMapperModel mapperModel, UserSessionModel userSession) {
    String prefix = mapperModel.getConfig().get(ATTRIBUTE_PREFIX);
    boolean strip = Boolean.parseBoolean(mapperModel.getConfig().get(STRIP_PREFIX));
    boolean jsonDecode = Boolean.parseBoolean(mapperModel.getConfig().get(JSON_DECODE));
    Map<String, List<String>> selected =
        PrefixSelectHelper.select(userSession.getUser().getAttributes(), prefix, strip);
    for (Map.Entry<String, List<String>> e : selected.entrySet()) {
      Object value = AttributeMapperHelper.emitValue(e.getValue(), jsonDecode);
      if (value != null) {
        token.getOtherClaims().put(e.getKey(), value);
      }
    }
  }
}
