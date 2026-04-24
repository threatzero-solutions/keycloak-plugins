package org.threatzero.keycloak.plugins.mappers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
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
 * Broker-time mapper that copies an OIDC claim value onto a user session note
 * during brokered login. Unlike Keycloak's built-in
 * {@code oidc-user-session-note-idp-mapper}, which only writes notes when
 * claims match specified values (a role-matching pattern), this mapper does a
 * plain copy with no match conditions — intended for general claim passthrough
 * pipelines.
 *
 * <h3>Configuration</h3>
 *
 * <ul>
 *   <li>{@code claim} (required): dotted claim path on the incoming token,
 *       e.g. {@code department} or {@code address.locality}. Matches the
 *       convention used by Keycloak's other OIDC claim mappers.
 *   <li>{@code user.session.note} (required): session-note key to write the
 *       claim value under.
 * </ul>
 *
 * <p>When the claim is missing or null the session note is not written.
 * Multi-value claims are stringified via {@code String.valueOf}, matching the
 * existing repo convention; if structured multi-value support is needed,
 * serialize JSON upstream or split into per-value mappers.
 */
public class OidcClaimToSessionNoteMapper extends AbstractClaimMapper {

  private static final String ID = "oidc-claim-to-session-note-idp-mapper";

  private static final String[] COMPATIBLE_PROVIDERS = {
    KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID
  };

  private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
      new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

  static final String CLAIM_NAME = "claim";
  static final String NOTE_KEY = "user.session.note";

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

    ProviderConfigProperty noteKey = new ProviderConfigProperty();
    noteKey.setName(NOTE_KEY);
    noteKey.setLabel("User Session Note");
    noteKey.setType(ProviderConfigProperty.STRING_TYPE);
    noteKey.setHelpText(
        "Key under which the claim value is stored on the user session note."
            + " Downstream protocol mappers (e.g. Keycloak's built-in User"
            + " Session Note mapper) can project the note onto issued tokens.");
    noteKey.setRequired(true);
    configProperties.add(noteKey);
  }

  @Override
  public void close() {}

  @Override
  public OidcClaimToSessionNoteMapper create(KeycloakSession session) {
    return new OidcClaimToSessionNoteMapper();
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
    return "Copies an OIDC claim value from the brokered token onto a user"
        + " session note with no match conditions. Pairs with the 'User Session"
        + " Note' protocol mapper (or a prefix-based variant) to forward claims"
        + " onto downstream tokens.";
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
    return "Claim to User Session Note";
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
    String claimName = mapperModel.getConfig().get(CLAIM_NAME);
    String noteKey = mapperModel.getConfig().get(NOTE_KEY);
    if (claimName == null
        || claimName.isEmpty()
        || noteKey == null
        || noteKey.isEmpty()) {
      return;
    }
    Object claimValue = getClaimValue(context, claimName);
    if (claimValue == null) {
      return;
    }
    context.setSessionNote(noteKey, String.valueOf(claimValue));
  }
}
