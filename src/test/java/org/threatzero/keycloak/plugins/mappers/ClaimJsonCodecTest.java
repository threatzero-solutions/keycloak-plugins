package org.threatzero.keycloak.plugins.mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class ClaimJsonCodecTest {

  // ----- encode -----

  @Test
  public void encodeNullReturnsNull() {
    assertNull(ClaimJsonCodec.encode(null, false));
    assertNull(ClaimJsonCodec.encode(null, true));
  }

  @Test
  public void encodeStringFlagOffUsesToString() {
    assertEquals("Security", ClaimJsonCodec.encode("Security", false));
  }

  @Test
  public void encodeListFlagOffUsesJavaToString() {
    // Legacy behavior — List.toString() format, not JSON.
    String out = ClaimJsonCodec.encode(List.of("a", "b"), false);
    assertEquals("[a, b]", out);
  }

  @Test
  public void encodeStringFlagOnQuotesAsJsonScalar() {
    // Distinct from flag-off: flag-on always produces valid JSON, so a
    // scalar string becomes a quoted JSON string. Decoders expecting JSON
    // can parse this unambiguously; decoders that skip parsing see the
    // quoted form (consumer's responsibility to know which mode was used).
    assertEquals("\"Security\"", ClaimJsonCodec.encode("Security", true));
  }

  @Test
  public void encodeListFlagOnProducesJsonArray() {
    assertEquals("[\"a\",\"b\"]", ClaimJsonCodec.encode(List.of("a", "b"), true));
  }

  @Test
  public void encodeMapFlagOnProducesJsonObject() {
    assertEquals(
        "{\"k\":\"v\"}",
        ClaimJsonCodec.encode(Map.of("k", "v"), true));
  }

  // ----- decode -----

  @Test
  public void decodeNullReturnsNull() {
    assertNull(ClaimJsonCodec.decode(null, false));
    assertNull(ClaimJsonCodec.decode(null, true));
  }

  @Test
  public void decodeFlagOffReturnsRawString() {
    assertEquals("anything", ClaimJsonCodec.decode("anything", false));
    assertEquals("[\"a\",\"b\"]", ClaimJsonCodec.decode("[\"a\",\"b\"]", false));
  }

  @Test
  public void decodeJsonArrayReturnsList() {
    Object out = ClaimJsonCodec.decode("[\"a\",\"b\"]", true);
    assertInstanceOf(List.class, out);
    assertEquals(List.of("a", "b"), out);
  }

  @Test
  public void decodeJsonObjectReturnsMap() {
    Object out = ClaimJsonCodec.decode("{\"k\":\"v\"}", true);
    assertInstanceOf(Map.class, out);
    assertEquals(Map.of("k", "v"), out);
  }

  @Test
  public void decodeJsonQuotedStringReturnsString() {
    Object out = ClaimJsonCodec.decode("\"Security\"", true);
    assertInstanceOf(String.class, out);
    assertEquals("Security", out);
  }

  @Test
  public void decodeInvalidJsonFallsBackToRawString() {
    // Values written with json.encode=false (Java toString output) aren't
    // valid JSON. Decoder must not throw; it returns the raw string so the
    // claim still reaches the token in some usable form.
    Object out = ClaimJsonCodec.decode("[SEC-ADMIN, IT-READ]", true);
    assertInstanceOf(String.class, out);
    assertEquals("[SEC-ADMIN, IT-READ]", out);
  }

  @Test
  public void decodePlainStringFlagOnFallsBackToRawString() {
    // A bare word isn't valid JSON either; same fallback path.
    Object out = ClaimJsonCodec.decode("Security", true);
    assertInstanceOf(String.class, out);
    assertEquals("Security", out);
  }

  // ----- round-trip -----

  @Test
  public void roundTripListPreservesStructure() {
    String encoded = ClaimJsonCodec.encode(List.of("a", "b"), true);
    Object decoded = ClaimJsonCodec.decode(encoded, true);
    assertEquals(List.of("a", "b"), decoded);
  }

  @Test
  public void roundTripScalarStringPreservesValue() {
    String encoded = ClaimJsonCodec.encode("Security", true);
    Object decoded = ClaimJsonCodec.decode(encoded, true);
    assertEquals("Security", decoded);
  }

  @Test
  public void roundTripNestedStructurePreservesShape() {
    Object original = Map.of("groups", List.of("SEC", "IT"), "dept", "Security");
    String encoded = ClaimJsonCodec.encode(original, true);
    Object decoded = ClaimJsonCodec.decode(encoded, true);
    assertEquals(original, decoded);
  }
}
