package org.threatzero.keycloak.plugins.services.admin.credentials;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriBuilder;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.authentication.requiredactions.util.RequiredActionsValidator;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * Admin endpoint that returns a one-time action-token URL for a user without sending Keycloak's
 * built-in email. Useful when the calling application wants to render its own branded onboarding
 * or password-reset email and embed the action link itself.
 *
 * <p>Mirrors the URL-construction pattern used by Keycloak's built-in {@code executeActionsEmail}
 * endpoint (see {@code UserResource#executeActionsEmail} in Keycloak 26.x): build an {@link
 * ExecuteActionsActionToken}, serialize it, and append the serialization as the {@code key} query
 * parameter on the realm's login-actions URL.
 *
 * <p>Authorization: requires the same admin permission as KC's {@code executeActionsEmail} —
 * {@code manage} on the target user.
 */
public class CredentialActionLinkResource {
  private static final Logger logger = Logger.getLogger(CredentialActionLinkResource.class);

  private final KeycloakSession session;
  private final RealmModel realm;
  private final AdminPermissionEvaluator auth;

  public CredentialActionLinkResource(
      KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
    this.session = session;
    this.realm = realm;
    this.auth = auth;
  }

  /**
   * Generate a one-time action-token URL for the given user.
   *
   * @param userId target user (Keycloak user UUID, required)
   * @param action required action to embed in the token (defaults to {@code UPDATE_PASSWORD}); must
   *     be one of the realm's enabled required-action providers
   * @param expirationSeconds token lifespan in seconds; defaults to the realm's
   *     {@code actionTokenGeneratedByAdminLifespan} setting
   * @param clientId OIDC client the action link is scoped to. Required — passing {@code null} here
   *     causes Keycloak to mint a token with a null issuer (see keycloak/keycloak#35317), which
   *     fails downstream validation.
   * @param redirectUri optional post-action redirect; must be a valid redirect URI for the client
   *     if provided
   * @return JSON body with {@code link}, {@code expiresAt} (ISO-8601), {@code tokenId} (the token
   *     JTI, useful for audit/correlation), and {@code action}
   */
  @GET
  @Path("/")
  @Produces(MediaType.APPLICATION_JSON)
  public Response generateLink(
      @QueryParam("userId") String userId,
      @QueryParam("action") String action,
      @QueryParam("expirationSeconds") Integer expirationSeconds,
      @QueryParam("clientId") String clientId,
      @QueryParam("redirectUri") String redirectUri) {
    if (userId == null || userId.isBlank()) {
      throw ErrorResponse.error("userId is required", Status.BAD_REQUEST);
    }
    if (clientId == null || clientId.isBlank()) {
      throw ErrorResponse.error("clientId is required", Status.BAD_REQUEST);
    }

    UserModel user = session.users().getUserById(realm, userId);
    if (user == null) {
      throw ErrorResponse.error("User not found", Status.NOT_FOUND);
    }

    auth.users().requireManage(user);

    if (realm.getClientByClientId(clientId) == null) {
      throw ErrorResponse.error("Unknown clientId", Status.BAD_REQUEST);
    }

    String resolvedAction = Optional.ofNullable(action).filter(a -> !a.isBlank()).orElse("UPDATE_PASSWORD");
    List<String> actions = List.of(resolvedAction);
    if (!RequiredActionsValidator.validRequiredActions(session, actions)) {
      throw ErrorResponse.error(
          "Action '" + resolvedAction + "' is not a valid required action in this realm",
          Status.BAD_REQUEST);
    }

    int lifespan =
        Optional.ofNullable(expirationSeconds)
            .filter(s -> s > 0)
            .orElse(realm.getActionTokenGeneratedByAdminLifespan());
    int expiration = Time.currentTime() + lifespan;

    ExecuteActionsActionToken token =
        new ExecuteActionsActionToken(
            user.getId(), user.getEmail(), expiration, actions, redirectUri, clientId);

    UriBuilder builder = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
    builder.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));
    String link = builder.build(realm.getName()).toString();

    logger.debugf(
        "Generated action-token link for user=%s action=%s lifespan=%ds jti=%s",
        user.getId(), resolvedAction, lifespan, token.getId());

    return Response.ok(
            new ActionLinkResponse(
                link,
                Instant.ofEpochSecond(expiration).toString(),
                token.getId(),
                user.getId(),
                resolvedAction))
        .build();
  }

  /** Response body for {@link #generateLink}. */
  public record ActionLinkResponse(
      String link, String expiresAt, String tokenId, String userId, String action) {}
}
