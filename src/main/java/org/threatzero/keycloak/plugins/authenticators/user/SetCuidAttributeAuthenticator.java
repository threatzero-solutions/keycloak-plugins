package org.threatzero.keycloak.plugins.authenticators.user;

import io.github.thibaultmeyer.cuid.CUID;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class SetCuidAttributeAuthenticator implements Authenticator {
  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();

    if (user != null) {
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();
      String attributeName = "cuid";
      boolean overwriteOnLogin = false;

      if (config != null) {
        attributeName =
            config.getConfig().get(SetCuidAttributeAuthenticatorFactory.ATTRIBUTE_NAME_CONFIG);
        overwriteOnLogin =
            Boolean.parseBoolean(
                config
                    .getConfig()
                    .get(SetCuidAttributeAuthenticatorFactory.OVERWRITE_ON_LOGIN_CONFIG));
      }

      String cuid = user.getFirstAttribute(attributeName);
      if (overwriteOnLogin || cuid == null || cuid.isEmpty()) {
        cuid = CUID.randomCUID2().toString(); // Generate a new CUID
        user.setSingleAttribute(attributeName, cuid);
      }
    }

    context.success();
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    authenticate(context);
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }
}
