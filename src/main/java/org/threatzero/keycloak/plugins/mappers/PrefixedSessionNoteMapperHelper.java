package org.threatzero.keycloak.plugins.mappers;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure helper for {@link PrefixedSessionNoteMapper}. Isolated so the
 * prefix-matching logic can be unit-tested without a Keycloak session.
 */
public final class PrefixedSessionNoteMapperHelper {

  private PrefixedSessionNoteMapperHelper() {}

  /**
   * Selects every entry of {@code notes} whose key starts with {@code prefix}
   * and returns a map keyed by the emitted claim name. When {@code stripPrefix}
   * is true, the prefix is removed from the emitted claim name.
   *
   * <p>Entries with a null/empty emitted claim name (e.g. the key equals the
   * prefix exactly and stripping is on) or a null value are omitted.
   *
   * <p>A null or empty {@code prefix} yields an empty map — callers treat an
   * unconfigured mapper as a no-op rather than a "forward everything" match.
   *
   * @param notes     session notes. {@code null} is treated as an empty map.
   * @param prefix    required non-empty key prefix.
   * @param stripPrefix whether to strip the prefix from the emitted claim name.
   * @return ordered map of claim name → value (insertion-ordered for
   *     deterministic emission).
   */
  public static Map<String, String> select(
      Map<String, String> notes, String prefix, boolean stripPrefix) {
    Map<String, String> out = new LinkedHashMap<>();
    if (notes == null || prefix == null || prefix.isEmpty()) {
      return out;
    }
    for (Map.Entry<String, String> entry : notes.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      if (key == null || value == null || !key.startsWith(prefix)) {
        continue;
      }
      String claim = stripPrefix ? key.substring(prefix.length()) : key;
      if (claim.isEmpty()) {
        continue;
      }
      out.put(claim, value);
    }
    return out;
  }
}
