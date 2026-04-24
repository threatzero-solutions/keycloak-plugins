package org.threatzero.keycloak.plugins.mappers;

import java.io.IOException;
import org.keycloak.util.JsonSerialization;

/**
 * Round-trips claim values through the Keycloak session-note store, which
 * is strictly string-typed (<code>Map&lt;String, String&gt;</code>), while
 * preserving the JSON structure of lists, maps, and other structured
 * claims when the caller opts in.
 *
 * <p>Usage is symmetric:
 *
 * <ul>
 *   <li>Broker-time mappers call {@link #encode(Object, boolean)} to turn
 *       an incoming claim value into a string suitable for
 *       <code>setSessionNote</code>.
 *   <li>Client-time protocol mappers call {@link #decode(String, boolean)}
 *       to turn a session-note string back into the original typed value
 *       (or an equivalent JSON tree) before writing it onto the token.
 * </ul>
 *
 * <p>When both sides enable the JSON flag, structured claims round-trip
 * losslessly: <code>{"g":["a","b"]}</code> goes in, <code>{"g":["a","b"]}</code>
 * comes out. When both sides leave it off, behavior matches the original
 * string-only path. Mixed configurations still work: if decode is enabled
 * but a particular note value isn't valid JSON (because the broker-side
 * flag was off or some other mapper wrote the note), decode falls back to
 * returning the raw string rather than throwing.
 */
public final class SessionNoteJsonCodec {

  private SessionNoteJsonCodec() {}

  /**
   * Serializes {@code value} to a string for storage as a session note.
   *
   * @param value the claim value to encode. {@code null} returns {@code null}.
   * @param jsonEncode when true, uses JSON serialization (preserves
   *     structure for lists, maps, and typed scalars). When false, uses
   *     {@link String#valueOf(Object)}, matching legacy behavior.
   * @return the encoded session-note value, or {@code null} if {@code value} was null.
   */
  public static String encode(Object value, boolean jsonEncode) {
    if (value == null) {
      return null;
    }
    if (!jsonEncode) {
      return String.valueOf(value);
    }
    try {
      return JsonSerialization.writeValueAsString(value);
    } catch (IOException e) {
      // Jackson serialization of in-memory Java values effectively never
      // fails; if it does, fall back to toString so we still emit something
      // rather than dropping the claim.
      return String.valueOf(value);
    }
  }

  /**
   * Deserializes a session-note string back into a typed claim value.
   *
   * @param sessionNoteValue the raw session-note value. {@code null} returns {@code null}.
   * @param jsonDecode when true, attempts JSON parsing; on success, returns
   *     the parsed tree (String, Number, Boolean, List, Map, etc.); on
   *     failure, falls back to the raw string. When false, returns the
   *     string verbatim.
   * @return the decoded value, suitable for
   *     {@code token.getOtherClaims().put(key, decoded)}.
   */
  public static Object decode(String sessionNoteValue, boolean jsonDecode) {
    if (sessionNoteValue == null) {
      return null;
    }
    if (!jsonDecode) {
      return sessionNoteValue;
    }
    try {
      return JsonSerialization.readValue(sessionNoteValue, Object.class);
    } catch (IOException e) {
      // Note was written without JSON encoding (or by some other mapper) —
      // return the raw string. This lets operators enable json.decode on a
      // prefixed-note mapper even while some notes under that prefix are
      // still plain strings.
      return sessionNoteValue;
    }
  }
}
