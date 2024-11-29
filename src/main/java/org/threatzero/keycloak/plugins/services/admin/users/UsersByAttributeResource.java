package org.threatzero.keycloak.plugins.services.admin.users;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.json.JsonReadFeature;
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
import jakarta.persistence.criteria.Selection;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.jpa.entities.UserGroupMembershipEntity;
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

  private final AtomicInteger attributeCount = new AtomicInteger(0);

  private final KeycloakSession session;
  private final RealmModel realm;
  private final AdminPermissionEvaluator auth;
  private final JsonMapper mapper =
      JsonMapper.builder()
          .findAndAddModules()
          // BEGIN Enable features for compatibility with JSON5.
          .enable(JsonReadFeature.ALLOW_UNQUOTED_FIELD_NAMES)
          .enable(JsonReadFeature.ALLOW_TRAILING_COMMA)
          .enable(JsonReadFeature.ALLOW_SINGLE_QUOTES)
          .enable(JsonReadFeature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER)
          .enable(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS)
          .enable(JsonReadFeature.ALLOW_JAVA_COMMENTS)
          .enable(JsonReadFeature.ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS)
          // END JSON5 features.
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
      @QueryParam("filter") String filter,
      @QueryParam("order") QueryOrder order,
      @QueryParam("limit") Integer limit,
      @QueryParam("offset") Integer offset) {
    // IMPORTANT: Check for permissions before executing query.
    auth.users().requireQuery();

    EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    CriteriaBuilder cb = em.getCriteriaBuilder();

    CriteriaQuery<Tuple> qb = cb.createTupleQuery();
    Root<UserEntity> root = qb.from(UserEntity.class);

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
    qb.distinct(true).select(cb.tuple(root)).where(buildPredicate(cb, root, queryFilter));

    // Set order by.
    if (order != null && !order.getValues().isEmpty()) {
      AtomicInteger idx = new AtomicInteger(0);
      qb.orderBy(
          order.getValues().stream()
              .map(
                  o -> {
                    String aliasName = "attribute_order_" + idx.getAndIncrement();
                    // If the sortable key comes from the user attributes table, we need to select
                    // the value for the given key to sort by it. Otherwise, we can simply use the
                    // key.
                    if (isAttributeName(o.getKey())) {
                      Join<UserEntity, UserAttributeEntity> attributesJoin =
                          root.join("attributes", JoinType.LEFT);
                      attributesJoin.on(
                          cb.and(
                              cb.equal(root.get("id"), attributesJoin.get("user").get("id")),
                              cb.equal(attributesJoin.get("name"), o.getKey())));
                      Expression<Number> valueExpr = attributesJoin.get("value");
                      Expression<Number> alias = o.isAsc() ? cb.min(valueExpr) : cb.max(valueExpr);
                      List<Selection<?>> existingSelections =
                          new ArrayList<>(qb.getSelection().getCompoundSelectionItems());
                      existingSelections.add(alias.alias(aliasName));
                      qb.distinct(true)
                          .select(cb.tuple(existingSelections.toArray(Selection[]::new)))
                          .groupBy(root);
                      return o.isAsc() ? cb.asc(alias) : cb.desc(alias);
                    } else {
                      Expression<String> alias = root.get(o.getKey());
                      return o.isAsc() ? cb.asc(alias) : cb.desc(alias);
                    }
                  })
              .toList());
    } else {
      qb.orderBy(cb.desc(root.get(CREATED_TIMESTAMP)));
    }

    // Limit and offset.
    TypedQuery<Tuple> query = em.createQuery(qb);
    int cleanedLimit = Math.min(Optional.ofNullable(limit).orElse(DEFAULT_LIMIT), MAX_LIMIT);
    query = query.setMaxResults(cleanedLimit);
    query = query.setFirstResult(Optional.ofNullable(offset).orElse(0));

    // Get results.
    List<UserRepresentation> results =
        query
            .getResultStream()
            .map(t -> t.get(0, UserEntity.class))
            .map(
                u ->
                    ModelToRepresentation.toRepresentation(
                        session, realm, new UserAdapter(session, realm, em, u)))
            .toList();
    results = populateGroups(em, cb, results);

    // Get total count.
    CriteriaQuery<Tuple> countQb = cb.createTupleQuery();
    Root<UserEntity> countRoot = countQb.from(UserEntity.class);

    countQb
        .select(cb.tuple(cb.countDistinct(countRoot.get("id"))))
        .where(buildPredicate(cb, countRoot, queryFilter));

    Long total =
        em.createQuery(countQb)
            .getResultStream()
            .findFirst()
            .map(t -> t.get(0, Long.class))
            .orElse(0L);

    // Build response.
    Paginated<UserRepresentation> page = new Paginated<>();
    page.setCount(total);
    page.setLimit(results.size());
    page.setOffset(query.getFirstResult());
    page.setResults(results);

    return Response.ok(page).build();
  }

  private Predicate buildPredicate(CriteriaBuilder cb, Root<UserEntity> root, QueryFilter filter) {
    // IMPORTANT: Base query should only include users from specified realm AND exclude all service
    // accounts.
    Predicate thePredicate =
        cb.and(
            cb.equal(root.get("realmId"), realm.getId()),
            root.get("serviceAccountClientLink").isNull());

    if (filter != null) {
      thePredicate = cb.and(thePredicate, getPredicate(cb, root, filter));
    }

    return thePredicate;
  }

  private Predicate getPredicate(CriteriaBuilder cb, Root<UserEntity> root, QueryFilter filter) {
    if (filter.getQ().isPresent()) {
      QueryFilter.Condition condition = filter.getQ().get();
      return getPredicate(cb, root, condition);
    } else if (filter.getAnd().isPresent()) {
      return cb.and(
          filter.getAnd().get().stream()
              .map(f -> getPredicate(cb, root, f))
              .toArray(Predicate[]::new));
    } else if (filter.getOr().isPresent()) {
      return cb.or(
          filter.getOr().get().stream()
              .map(f -> getPredicate(cb, root, f))
              .toArray(Predicate[]::new));
    }
    return cb.conjunction();
  }

  private Predicate getPredicate(
      CriteriaBuilder cb, Root<UserEntity> root, QueryFilter.Condition condition) {
    Boolean ignoreCase = condition.isIgnoreCase().orElse(true);

    List<String> values = condition.getValues();
    if (ignoreCase) {
      values = values.stream().map(String::toLowerCase).toList();
    }

    String value = values.get(0);
    QueryFilter.Condition.Operator operator =
        condition.getOp().orElse(QueryFilter.Condition.Operator.EQ);

    String attributeName = condition.getKey();
    Join<UserEntity, UserAttributeEntity> attributesJoin = null;
    Expression<String> alias;
    if (isAttributeName(attributeName)) {
      attributesJoin = root.join("attributes");
      attributesJoin.alias("ua" + attributeCount.incrementAndGet());
      alias = attributesJoin.get("value");
    } else {
      alias = root.get(attributeName);
    }

    if (ignoreCase) {
      alias = cb.lower(alias);
    }

    Predicate thePredicate;

    switch (operator) {
      case IN:
        thePredicate = alias.in(values);
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

    if (attributesJoin != null) {
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

  private List<UserRepresentation> populateGroups(
      EntityManager em, CriteriaBuilder cb, List<UserRepresentation> users) {

    CriteriaQuery<Tuple> qb = cb.createTupleQuery();
    Root<UserGroupMembershipEntity> membershipRoot = qb.from(UserGroupMembershipEntity.class);
    Root<GroupEntity> groupRoot = qb.from(GroupEntity.class);

    Predicate thisPredicate =
        cb.and(
            membershipRoot.get("user").get("id").in(users.stream().map(u -> u.getId()).toList()),
            cb.equal(groupRoot.get("id"), membershipRoot.get("groupId")),
            cb.equal(groupRoot.get("type"), GroupModel.Type.REALM.intValue()));

    qb.select(cb.tuple(membershipRoot.get("user").get("id"), groupRoot)).where(thisPredicate);

    TypedQuery<Tuple> query = em.createQuery(qb);
    Map<String, List<GroupEntity>> userGroupMap =
        query
            .getResultStream()
            .collect(
                Collectors.groupingBy(
                    t -> t.get(0, String.class),
                    Collectors.mapping(t -> t.get(1, GroupEntity.class), Collectors.toList())));

    return users.stream()
        .map(
            u -> {
              u.setGroups(
                  userGroupMap.getOrDefault(u.getId(), List.of()).stream()
                      .map(
                          g ->
                              ModelToRepresentation.toRepresentation(
                                      new GroupAdapter(session, realm, em, g), false)
                                  .getPath())
                      .toList());
              return u;
            })
        .toList();
  }
}
