package org.threatzero.keycloak.plugins.services.models;

import java.util.List;
import lombok.Data;

@Data
public class Paginated<T> {
  private List<T> results;
  private Long count;
  private int limit;
  private int offset;
}
