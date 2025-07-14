package org.threatzero.keycloak.plugins.services.admin.users;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public class UsersByAttributeResourceProvider
    implements AdminRealmResourceProvider, AdminRealmResourceProviderFactory {
  private static final String ID = "users-by-attribute";

  @Override
  public AdminRealmResourceProvider create(KeycloakSession session) {
    return this;
  }

  @Override
  public void init(Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public Object getResource(
      KeycloakSession session,
      RealmModel realm,
      AdminPermissionEvaluator auth,
      AdminEventBuilder event) {
    return new UsersByAttributeResource(session, realm, auth, event);
  }
}
