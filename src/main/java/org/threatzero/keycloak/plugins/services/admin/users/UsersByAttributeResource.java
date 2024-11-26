package org.threatzero.keycloak.plugins.services.admin.users;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Tuple;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Optional;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.threatzero.keycloak.plugins.services.models.Paginated;
import org.threatzero.keycloak.plugins.services.models.QueryFilter;
import org.threatzero.keycloak.plugins.services.models.QueryOrder;

public class UsersByAttributeResource {
  private static final Logger logger = Logger.getLogger(UsersByAttributeResource.class);

  private static final String CREATED_TIMESTAMP = "createdTimestamp";

  private static final int DEFAULT_LIMIT = 10;
  private static final int MAX_LIMIT = 1000;

  private final KeycloakSession session;
  private final RealmModel realm;
  private final AdminPermissionEvaluator auth;
  private final JsonMapper mapper =
      JsonMapper.builder()
          .findAndAddModules()
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .serializationInclusion(Include.NON_ABSENT)
          .build();

  public UsersByAttributeResource(
      KeycloakSession session,
      RealmModel realm,
      AdminPermissionEvaluator auth,
      AdminEventBuilder event) {
    this.session = session;
    this.realm = realm;
    this.auth = auth;
  }

  @GET
  @Path("/")
  @Produces(MediaType.APPLICATION_JSON)
  public Response getUsersByAttribute(
      @QueryParam("filter") String filter, @QueryParam("order") QueryOrder order, @QueryParam("limit") Integer limit, 
      @QueryParam("offset") Integer offset) {
    // IMPORTANT: Check for permissions before executing query.
    auth.users().requireQuery();

    EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    CriteriaBuilder cb = em.getCriteriaBuilder();

    CriteriaQuery<UserEntity> qb = cb.createQuery(UserEntity.class);
    Root<UserEntity> root = qb.from(UserEntity.class);
    Join<UserEntity, UserAttributeEntity> attributesJoin = root.join("attributes", JoinType.LEFT);

    QueryFilter queryFilter = null;
    if (filter != null) {
      try {
        queryFilter = mapper.readValue(filter, QueryFilter.class);
      } catch (Exception e) {
        logger.error("Failed to parse filter", e);
        return Response.status(Response.Status.BAD_REQUEST).build();
      }
    }

    // Apply query filter to where clause.
    qb.where(buildPredicate(cb, root, attributesJoin, queryFilter));

    // Set order by.
    if (order != null && !order.getValues().isEmpty()) {
      qb.orderBy(
          order.getValues().stream()
              .map(
                  o -> {
                    // If the sortable key comes from the user attributes table, we need to select
                    // the value for the given key to sort by it. Otherwise, we can simply use the
                    // key.
                    Expression<Object> alias;
                    if (isAttributeName(o.getKey())) {
                      Expression<Object> selectExpression =
                          cb.selectCase()
                              .when(
                                  cb.equal(attributesJoin.get("name"), o.getKey()),
                                  attributesJoin.get("value"))
                              .otherwise(cb.nullLiteral(String.class));
                      alias = selectExpression;
                    } else {
                      alias = root.get(o.getKey());
                    }
                    return o.isAsc() ? cb.asc(alias) : cb.desc(alias);
                  })
              .toList());
    } else {
      qb.orderBy(cb.desc(root.get(CREATED_TIMESTAMP)));
    }

    // Limit and offset.
    TypedQuery<UserEntity> query = em.createQuery(qb);
    int cleanedLimit = Math.min(Optional.ofNullable(limit).orElse(DEFAULT_LIMIT), MAX_LIMIT);
    query = query.setMaxResults(cleanedLimit);
    query = query.setFirstResult(Optional.ofNullable(offset).orElse(0));

    // Get results.
    List<UserRepresentation> results =
        query
            .getResultStream()
            .map(
                u ->
                    ModelToRepresentation.toRepresentation(
                        session, realm, new UserAdapter(session, realm, em, u)))
            .toList();

    // Get total count.
    CriteriaQuery<Tuple> countQb = cb.createTupleQuery();
    Root<UserEntity> countRoot = countQb.from(UserEntity.class);
    Join<UserEntity, UserAttributeEntity> countAttributesJoin =
        countRoot.join("attributes", JoinType.LEFT);

    countQb
        .select(cb.tuple(cb.count(countRoot.get("id"))))
        .where(buildPredicate(cb, countRoot, countAttributesJoin, queryFilter))
        .groupBy(countRoot.get("realmId"));

    Tuple countResults = em.createQuery(countQb).getSingleResult();
    Long total = countResults.get(0, Long.class);

    // Build response.
    Paginated<UserRepresentation> page = new Paginated<>();
    page.setCount(total);
    page.setLimit(results.size());
    page.setOffset(query.getFirstResult());
    page.setResults(results);

    return Response.ok(page).build();
  }

  private Predicate buildPredicate(
      CriteriaBuilder cb,
      Root<UserEntity> root,
      Join<UserEntity, UserAttributeEntity> attributesJoin,
      QueryFilter filter) {
    // IMPORTANT: Base query should only include users from specified realm AND exclude all service
    // accounts.
    Predicate thePredicate =
        cb.and(
            cb.equal(root.get("realmId"), realm.getId()),
            root.get("serviceAccountClientLink").isNull());

    if (filter != null) {
      thePredicate = cb.and(thePredicate, getPredicate(cb, root, attributesJoin, filter));
    }

    return thePredicate;
  }

  private Predicate getPredicate(
      CriteriaBuilder cb,
      Root<UserEntity> root,
      Join<UserEntity, UserAttributeEntity> attributesJoin,
      QueryFilter filter) {
    if (filter.getQ().isPresent()) {
      QueryFilter.Condition condition = filter.getQ().get();
      return getPredicate(cb, root, attributesJoin, condition);
    } else if (filter.getAnd().isPresent()) {
      return cb.and(
          filter.getAnd().get().stream()
              .map(f -> getPredicate(cb, root, attributesJoin, f))
              .toArray(Predicate[]::new));
    } else if (filter.getOr().isPresent()) {
      return cb.or(
          filter.getOr().get().stream()
              .map(f -> getPredicate(cb, root, attributesJoin, f))
              .toArray(Predicate[]::new));
    }
    return null;
  }

  private Predicate getPredicate(
      CriteriaBuilder cb,
      Root<UserEntity> root,
      Join<UserEntity, UserAttributeEntity> attributesJoin,
      QueryFilter.Condition condition) {
    Boolean ignoreCase = condition.isIgnoreCase().orElse(true);

    List<String> values = condition.getValues();
    if (ignoreCase) {
      values = values.stream().map(String::toLowerCase).toList();
    }

    String value = values.get(0);
    QueryFilter.Condition.Operator operator =
        condition.getOp().orElse(QueryFilter.Condition.Operator.EQ);

    String attributeName = condition.getKey();
    boolean isAttribute = false;
    Expression<String> alias;
    if (isAttributeName(attributeName)) {
      alias = attributesJoin.get("value");
      isAttribute = true;
    } else {
      alias = root.get(attributeName);
    }

    if (ignoreCase) {
      alias = cb.lower(alias);
    }

    Predicate thePredicate;

    switch (operator) {
      case IN:
        thePredicate = cb.in(alias).in(values);
        break;
      case CONTAINS:
        thePredicate = cb.like(alias, "%" + value + "%");
        break;
      case STARTS:
        thePredicate = cb.like(alias, value + "%");
        break;
      case ENDS:
        thePredicate = cb.like(alias, "%" + value);
        break;
      case GT:
        thePredicate = cb.greaterThan(alias, value);
        break;
      case GTE:
        thePredicate = cb.greaterThanOrEqualTo(alias, value);
        break;
      case LT:
        thePredicate = cb.lessThan(alias, value);
        break;
      case LTE:
        thePredicate = cb.lessThanOrEqualTo(alias, value);
        break;
      case EQ:
      default:
        thePredicate = cb.equal(alias, value);
        break;
    }

    if (condition.isNot().orElse(false)) {
      thePredicate = cb.not(thePredicate);
    }

    if (isAttribute) {
      thePredicate = cb.and(cb.equal(attributesJoin.get("name"), attributeName), thePredicate);
    }

    return thePredicate;
  }

  private boolean isAttributeName(String name) {
    switch (name) {
      case UserModel.USERNAME:
      case UserModel.EMAIL:
      case UserModel.FIRST_NAME:
      case UserModel.LAST_NAME:
      case UserModel.EMAIL_VERIFIED:
      case UserModel.ENABLED:
      case CREATED_TIMESTAMP:
        return false;
      default:
        return true;
    }
  }
}
