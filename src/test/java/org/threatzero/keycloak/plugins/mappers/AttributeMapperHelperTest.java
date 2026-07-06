package org.threatzero.keycloak.plugins.mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class AttributeMapperHelperTest {

  // --- resolveWrite: the broker-time set-or-remove decision ---

  @Test
  public void absentClaimSignalsRemoval() {
    // Clear-on-absent: a persisted attribute must not outlive the claim.
    assertTrue(AttributeMapperHelper.resolveWrite(null, false).isEmpty());
    assertTrue(AttributeMapperHelper.resolveWrite(null, true).isEmpty());
  }

  @Test
  public void scalarClaimWritesPlainString() {
    assertEquals(
        Optional.of("Security"), AttributeMapperHelper.resolveWrite("Security", false));
  }

  @Test
  public void structuredClaimWritesJsonWhenEncodingEnabled() {
    assertEquals(
        Optional.of("[\"a\",\"b\"]"),
        AttributeMapperHelper.resolveWrite(List.of("a", "b"), true));
  }

  @Test
  public void structuredClaimWithoutEncodingFallsBackToStringValueOf() {
    assertEquals(
        Optional.of("[a, b]"), AttributeMapperHelper.resolveWrite(List.of("a", "b"), false));
  }

  // --- emitValue: the token-mint-time attribute-list → claim decision ---

  @Test
  public void nullOrEmptyListEmitsNothing() {
    assertNull(AttributeMapperHelper.emitValue(null, false));
    assertNull(AttributeMapperHelper.emitValue(List.of(), false));
    assertNull(AttributeMapperHelper.emitValue(null, true));
    assertNull(AttributeMapperHelper.emitValue(List.of(), true));
  }

  @Test
  public void singleValueEmitsScalarString() {
    assertEquals("security", AttributeMapperHelper.emitValue(List.of("security"), false));
  }

  @Test
  public void singleJsonArrayValueDecodesToList() {
    Object out = AttributeMapperHelper.emitValue(List.of("[\"a\",\"b\"]"), true);
    assertEquals(List.of("a", "b"), out);
  }

  @Test
  public void singleJsonObjectValueDecodesToMap() {
    Object out = AttributeMapperHelper.emitValue(List.of("{\"unit\":\"emea\"}"), true);
    assertInstanceOf(Map.class, out);
    assertEquals("emea", ((Map<?, ?>) out).get("unit"));
  }

  @Test
  public void singleNonJsonValueFallsBackToRawString() {
    // String.valueOf output of a list isn't valid JSON — must not throw.
    assertEquals("[a, b]", AttributeMapperHelper.emitValue(List.of("[a, b]"), true));
  }

  @Test
  public void multiValueEmitsArrayOfStrings() {
    assertEquals(
        List.of("a", "b"), AttributeMapperHelper.emitValue(List.of("a", "b"), false));
  }

  @Test
  public void multiValueDecodesEachElementIndependently() {
    Object out = AttributeMapperHelper.emitValue(List.of("[\"x\"]", "true"), true);
    assertEquals(List.of(List.of("x"), true), out);
  }

  @Test
  public void multiValueWithMixedJsonAndPlainElementsFallsBackPerElement() {
    Object out = AttributeMapperHelper.emitValue(List.of("[\"x\"]", "plain"), true);
    assertEquals(List.of(List.of("x"), "plain"), out);
  }

  // --- write-then-emit round-trip parity (json.encode ⇄ json.decode) ---

  @Test
  public void structuredClaimRoundTripsThroughSingleValuedAttribute() {
    Object claim = List.of("a", "b");
    String stored = AttributeMapperHelper.resolveWrite(claim, true).orElseThrow();
    assertEquals(claim, AttributeMapperHelper.emitValue(List.of(stored), true));
  }
}
