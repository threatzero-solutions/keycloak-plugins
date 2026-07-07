package org.threatzero.keycloak.plugins.mappers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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

/**
 * Broker-time mapper that copies an OIDC claim value onto a <em>persisted
 * user attribute</em> during brokered login. The attribute-based sibling of
 * {@link OidcClaimToSessionNoteMapper}: same plain no-match-condition copy,
 * but the value survives beyond the brokered session — so downstream
 * protocol mappers (pair with {@code oidc-prefixed-attribute-mapper}) can
 * emit it on tokens minted through <em>any</em> path, including
 * impersonation, direct-grant/password fallback, and the RFC 7523 JWT
 * Authorization Grant, none of which replay the broker pipeline.
 *
 * <h3>Configuration</h3>
 *
 * <ul>
 *   <li>{@code claim} (required): dotted claim path on the incoming token,
 *       e.g. {@code department} or {@code address.locality}. Matches the
 *       convention used by Keycloak's other OIDC claim mappers.
 *   <li>{@code user.attribute} (required): user attribute to write the claim
 *       value to. Always written single-valued; enable {@code json.encode}
 *       to carry lists or objects losslessly.
 *   <li>{@code json.encode} (default {@code false}): JSON-serialize the
 *       claim value before writing, preserving structure through the
 *       string-typed attribute store. Pair with {@code json.decode} on the
 *       prefixed-attribute protocol mapper.
 * </ul>
 *
 * <h3>Clear-on-absent (differs from the session-note mapper)</h3>
 *
 * <p>When the claim is missing from the incoming token the attribute is
 * <em>removed</em>, not left alone. Session notes die with the session, so a
 * skipped write is harmless there — but a persisted attribute would keep the
 * previous login's value at rest and misrepresent the IDP's current truth
 * (an escalation risk when authorization keys off the attribute). Use sync
 * mode FORCE so this update runs on every login; with IMPORT the mapper only
 * runs at first broker login and the attribute goes stale.
 *
 * <h3>Realm prerequisite</h3>
 *
 * <p>With Keycloak's declarative user profile, writes to an undeclared
 * (unmanaged) attribute are silently dropped at commit. The realm must
 * either declare the target attribute in the user profile or permit
 * unmanaged attributes — use {@code unmanagedAttributePolicy=ADMIN_EDIT}
 * (never {@code ENABLED}) so users cannot edit authorization-relevant
 * attributes about themselves through the account console.
 */
public class OidcClaimToAttributeMapper extends AbstractClaimMapper {

  private static final String ID = "oidc-claim-to-attribute-idp-mapper";

  private static final String[] COMPATIBLE_PROVIDERS = {
    KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID
  };

  private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
      new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

  static final String CLAIM_NAME = "claim";
  static final String ATTRIBUTE_NAME = "user.attribute";
  static final String JSON_ENCODE = "json.encode";

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  static {
    ProviderConfigProperty claim = new ProviderConfigProperty();
    claim.setName(CLAIM_NAME);
    claim.setLabel("Claim");
    claim.setType(ProviderConfigProperty.STRING_TYPE);
    claim.setHelpText(
        "Name of the claim to copy from the incoming token. Reference nested"
            + " claims with '.', e.g. 'address.locality'. Escape literal dots"
            + " with a backslash (\\.).");
    claim.setRequired(true);
    configProperties.add(claim);

    ProviderConfigProperty attributeName = new ProviderConfigProperty();
    attributeName.setName(ATTRIBUTE_NAME);
    attributeName.setLabel("User Attribute Name");
    attributeName.setType(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE);
    attributeName.setHelpText(
        "User attribute to write the claim value to. When the claim is absent"
            + " from the incoming token the attribute is removed, so with sync"
            + " mode FORCE the attribute tracks the identity provider's current"
            + " truth on every login. Downstream protocol mappers (e.g."
            + " oidc-prefixed-attribute-mapper) can project the attribute onto"
            + " issued tokens.");
    attributeName.setRequired(true);
    configProperties.add(attributeName);

    ProviderConfigProperty jsonEncode = new ProviderConfigProperty();
    jsonEncode.setName(JSON_ENCODE);
    jsonEncode.setLabel("JSON-Encode Value");
    jsonEncode.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    jsonEncode.setHelpText(
        "When true, the claim value is JSON-serialized before being written"
            + " to the user attribute, preserving lists and nested structures"
            + " through the string-typed attribute store. Pair with a decoding"
            + " protocol mapper (e.g. oidc-prefixed-attribute-mapper with"
            + " json.decode enabled) to emit the claim as structured JSON on"
            + " the issued token. When false (default), values are stored via"
            + " String.valueOf — acceptable for scalar claims only.");
    jsonEncode.setDefaultValue("false");
    jsonEncode.setRequired(false);
    configProperties.add(jsonEncode);
  }

  @Override
  public void close() {}

  @Override
  public OidcClaimToAttributeMapper create(KeycloakSession session) {
    return new OidcClaimToAttributeMapper();
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
    return "Copies an OIDC claim value from the brokered token onto a persisted"
        + " user attribute with no match conditions, removing the attribute"
        + " when the claim is absent. Pairs with the 'Prefixed attributes'"
        + " protocol mapper to forward claims onto downstream tokens — including"
        + " tokens minted outside the broker flow (impersonation, JWT"
        + " authorization grant).";
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
    return "Claim to Attribute";
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
    String claimName = mapperModel.getConfig().get(CLAIM_NAME);
    String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
    if (claimName == null
        || claimName.isEmpty()
        || attributeName == null
        || attributeName.isEmpty()) {
      return;
    }
    Object claimValue = getClaimValue(context, claimName);
    boolean jsonEncode = Boolean.parseBoolean(mapperModel.getConfig().get(JSON_ENCODE));
    Optional<String> write = AttributeMapperHelper.resolveWrite(claimValue, jsonEncode);
    if (write.isPresent()) {
      user.setSingleAttribute(attributeName, write.get());
    } else {
      // Clear-on-absent: on importNewUser this is a no-op (fresh user), on
      // FORCE re-logins it drops values the IDP no longer asserts.
      user.removeAttribute(attributeName);
    }
  }
}
