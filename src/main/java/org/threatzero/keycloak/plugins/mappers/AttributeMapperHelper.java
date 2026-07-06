package org.threatzero.keycloak.plugins.mappers;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Pure helpers for the attribute-based claim mappers ({@link
 * OidcClaimToAttributeMapper}, {@link PrefixedAttributeMapper}). Isolated so
 * the write/emit decisions can be unit-tested without a Keycloak session.
 */
public final class AttributeMapperHelper {

  private AttributeMapperHelper() {}

  /**
   * Decides what a broker-time attribute write should do for a claim value.
   *
   * <p>An empty result means the claim is absent from the incoming token and
   * the caller must <em>remove</em> the attribute (clear-on-absent) — a
   * persisted attribute lives at rest, so a stale value from a prior login
   * would otherwise misrepresent the IDP's current truth. A present result is
   * the encoded string to store via {@code setSingleAttribute}.
   *
   * @param claimValue the claim value extracted from the brokered token; may
   *     be {@code null} when the claim is absent.
   * @param jsonEncode when true, structured values are JSON-serialized so
   *     they round-trip losslessly through the string-typed attribute value
   *     (pair with {@code json.decode} on the emitting protocol mapper).
   * @return the string to write, or empty to signal attribute removal.
   */
  public static Optional<String> resolveWrite(Object claimValue, boolean jsonEncode) {
    return Optional.ofNullable(ClaimJsonCodec.encode(claimValue, jsonEncode));
  }

  /**
   * Converts a user-attribute value list into the claim value to emit on a
   * token.
   *
   * <ul>
   *   <li>{@code null} or empty list → {@code null} (caller skips the claim).
   *   <li>Single value → scalar: the raw string, or its JSON-decoded form
   *       when {@code jsonDecode} is true (invalid JSON falls back to the raw
   *       string, so mixing encoded and plain values under one prefix is
   *       safe).
   *   <li>Multiple values → array: each element decoded independently under
   *       the same rule.
   * </ul>
   *
   * @param values the attribute value list from {@code UserModel.getAttributes()}.
   * @param jsonDecode whether to JSON-decode each stored value.
   * @return the claim value to emit, or {@code null} to emit nothing.
   */
  public static Object emitValue(List<String> values, boolean jsonDecode) {
    if (values == null || values.isEmpty()) {
      return null;
    }
    if (values.size() == 1) {
      return ClaimJsonCodec.decode(values.get(0), jsonDecode);
    }
    List<Object> out = new ArrayList<>();
    for (String value : values) {
      out.add(ClaimJsonCodec.decode(value, jsonDecode));
    }
    return out;
  }
}
