package org.threatzero.keycloak.plugins.services.models;

import java.util.ArrayList;
import java.util.List;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;

@Getter
public class QueryOrder {
  private List<Order> values = new ArrayList<>();

  public QueryOrder(String value) {
    for (String s : value.split(",")) {
      Order.OrderBuilder orderBuilder = Order.builder();
      if (s.startsWith("-")) {
        String key = s.substring(1);
        orderBuilder = orderBuilder.key(key).asc(false);
      } else {
        orderBuilder = orderBuilder.key(s).asc(true);
      }
      values.add(orderBuilder.build());
    }
  }

  @Data
  @Builder
  public static class Order {
    private final String key;
    private final boolean asc;
  }
}
