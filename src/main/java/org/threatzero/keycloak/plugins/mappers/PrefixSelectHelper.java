package org.threatzero.keycloak.plugins.mappers;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure prefix-selection helper shared by the prefixed protocol mappers
 * ({@link PrefixedSessionNoteMapper} over session notes, {@link
 * PrefixedAttributeMapper} over user attributes). Isolated so the
 * prefix-matching logic can be unit-tested without a Keycloak session.
 */
public final class PrefixSelectHelper {

  private PrefixSelectHelper() {}

  /**
   * Selects every entry of {@code source} whose key starts with {@code prefix}
   * and returns a map keyed by the emitted claim name. When {@code stripPrefix}
   * is true, the prefix is removed from the emitted claim name.
   *
   * <p>Entries with a null/empty emitted claim name (e.g. the key equals the
   * prefix exactly and stripping is on) or a null value are omitted. Values
   * are passed through untouched — emptiness of a container value (e.g. an
   * empty attribute list) is the caller's concern, not selection's.
   *
   * <p>A null or empty {@code prefix} yields an empty map — callers treat an
   * unconfigured mapper as a no-op rather than a "forward everything" match.
   *
   * @param source    key/value store to select from (session notes are
   *     {@code Map<String, String>}, user attributes are
   *     {@code Map<String, List<String>>}). {@code null} is treated as empty.
   * @param prefix    required non-empty key prefix.
   * @param stripPrefix whether to strip the prefix from the emitted claim name.
   * @return ordered map of claim name → value (insertion-ordered for
   *     deterministic emission).
   */
  public static <V> Map<String, V> select(
      Map<String, V> source, String prefix, boolean stripPrefix) {
    Map<String, V> out = new LinkedHashMap<>();
    if (source == null || prefix == null || prefix.isEmpty()) {
      return out;
    }
    for (Map.Entry<String, V> entry : source.entrySet()) {
      String key = entry.getKey();
      V value = entry.getValue();
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
