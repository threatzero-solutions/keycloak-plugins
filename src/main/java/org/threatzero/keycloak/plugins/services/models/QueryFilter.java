package org.threatzero.keycloak.plugins.services.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.List;
import java.util.Optional;
import lombok.Data;

@Data
public class QueryFilter {
  @JsonProperty("AND")
  private List<QueryFilter> and;

  @JsonProperty("OR")
  private List<QueryFilter> or;

  private Condition condition;

  public Optional<List<QueryFilter>> getAnd() {
    return Optional.ofNullable(and);
  }

  public Optional<List<QueryFilter>> getOr() {
    return Optional.ofNullable(or);
  }

  public Optional<Condition> getCondition() {
    return Optional.ofNullable(condition);
  }

  @Data
  public static class Condition {
    @JsonProperty(required = true)
    private String attribute;

    private Operator operator;

    @JsonProperty(value = "value", required = true)
    private List<String> values;

    private Boolean negate;
    private Boolean ignoreCase;

    public void setValues(List<String> values) {
      if (values == null || values.isEmpty()) {
        throw new IllegalArgumentException("values cannot be null or empty");
      }
      this.values = values;
    }

    public void setValues(String... values) {
      this.values = List.of(values);
    }

    public void setValue(String value) {
      this.values = List.of(value);
    }

    @JsonSetter("value")
    @SuppressWarnings("unchecked")
    public void setValue(Object value) {
      if (value instanceof String) {
        setValue((String) value);
      } else if (value instanceof List
          && ((List<?>) value).stream().allMatch(el -> el instanceof String)) {
        setValues((List<String>) value);
      } else {
        throw new IllegalArgumentException("value must be a string or a list of strings");
      }
    }

    public Optional<Operator> getOperator() {
      return Optional.ofNullable(operator);
    }

    public Optional<Boolean> isNegate() {
      return Optional.ofNullable(negate);
    }

    public Optional<Boolean> isIgnoreCase() {
      return Optional.ofNullable(ignoreCase);
    }

    public static enum Operator {
      EQUALS,
      IN,
      STARTS_WITH,
      ENDS_WITH,
      CONTAINS,
      GREATER_THAN,
      GREATER_THAN_OR_EQUAL,
      LESS_THAN,
      LESS_THAN_OR_EQUAL;

      @JsonCreator
      public static Operator fromString(String operator) {
        if (operator == null) {
          return null;
        }
        try {
          return Operator.valueOf(operator.toUpperCase());
        } catch (IllegalArgumentException e) {
          return null;
        }
      }

      @JsonValue
      public String toString() {
        return name().toLowerCase();
      }
    }
  }
}