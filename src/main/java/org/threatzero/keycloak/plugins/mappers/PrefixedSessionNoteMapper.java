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
 * Forwards every user session note whose key starts with a configured prefix
 * onto the access, ID, and/or UserInfo token as a claim of the same name.
 *
 * <p>Keycloak's built-in {@code oidc-usersessionnote-mapper} requires one
 * instance per (session-note, token-claim) pair. When the set of notes is
 * admin-configured at runtime — e.g., an identity-broker pipeline that
 * imports an arbitrary number of upstream claims under a common namespace —
 * pre-authoring a mapper per note is either impractical or dual-write. This
 * mapper takes a prefix instead, so a single instance forwards the whole
 * namespace.
 *
 * <h3>Configuration</h3>
 *
 * <ul>
 *   <li>{@code note.prefix} (required): session notes whose key starts with
 *       this prefix are forwarded. Example: {@code tz.idp.}
 *   <li>{@code strip.prefix} (default {@code false}): when true, the prefix
 *       is removed from the emitted claim name. {@code tz.idp.department}
 *       becomes claim {@code department} on the token.
 *   <li>Standard OIDC flags ({@code access.token.claim},
 *       {@code id.token.claim}, {@code userinfo.token.claim}): control which
 *       tokens the claims are added to.
 * </ul>
 *
 * <h3>Value handling</h3>
 *
 * <p>Session notes are string-valued. Each matching note is emitted verbatim
 * as a string claim. Notes with a null value are skipped.
 */
public class PrefixedSessionNoteMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

  public static final String PROVIDER_ID = "oidc-prefixed-session-note-mapper";

  static final String NOTE_PREFIX = "note.prefix";
  static final String STRIP_PREFIX = "strip.prefix";

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  static {
    ProviderConfigProperty prefix = new ProviderConfigProperty();
    prefix.setName(NOTE_PREFIX);
    prefix.setLabel("Session Note Prefix");
    prefix.setType(ProviderConfigProperty.STRING_TYPE);
    prefix.setHelpText(
        "Every session note whose key starts with this prefix is forwarded as a"
            + " token claim. Example: 'tz.idp.' forwards note 'tz.idp.department'"
            + " as claim 'tz.idp.department' (or 'department' if Strip Prefix is"
            + " enabled).");
    prefix.setRequired(true);
    configProperties.add(prefix);

    ProviderConfigProperty strip = new ProviderConfigProperty();
    strip.setName(STRIP_PREFIX);
    strip.setLabel("Strip Prefix From Claim Name");
    strip.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    strip.setHelpText(
        "When true, the prefix is removed from the emitted claim name. Leave"
            + " disabled to preserve the full session-note key on the token.");
    strip.setDefaultValue("false");
    strip.setRequired(false);
    configProperties.add(strip);

    OIDCAttributeMapperHelper.addIncludeInTokensConfig(
        configProperties, PrefixedSessionNoteMapper.class);
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
    return "Prefixed session notes";
  }

  @Override
  public String getHelpText() {
    return "Forwards every user session note whose key starts with a configured"
        + " prefix as a token claim. Useful for passing through a dynamic"
        + " namespace of claims (e.g. 'tz.idp.*') without pre-authoring a mapper"
        + " per claim.";
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
    String prefix = mapperModel.getConfig().get(NOTE_PREFIX);
    boolean strip = Boolean.parseBoolean(mapperModel.getConfig().get(STRIP_PREFIX));
    Map<String, String> selected =
        PrefixedSessionNoteMapperHelper.select(userSession.getNotes(), prefix, strip);
    for (Map.Entry<String, String> e : selected.entrySet()) {
      token.getOtherClaims().put(e.getKey(), e.getValue());
    }
  }
}
