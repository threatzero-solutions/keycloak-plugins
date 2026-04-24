package org.threatzero.keycloak.plugins.mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class PrefixedSessionNoteMapperHelperTest {

  private static Map<String, String> notes(String... kv) {
    Map<String, String> m = new LinkedHashMap<>();
    for (int i = 0; i < kv.length; i += 2) {
      m.put(kv[i], kv[i + 1]);
    }
    return m;
  }

  @Test
  public void selectsOnlyMatchingPrefix() {
    Map<String, String> result =
        PrefixedSessionNoteMapperHelper.select(
            notes(
                "tz.idp.department", "security",
                "tz.idp.region", "emea",
                "sub", "abc-123",
                "preferred_username", "alice"),
            "tz.idp.",
            false);

    assertEquals(2, result.size());
    assertEquals("security", result.get("tz.idp.department"));
    assertEquals("emea", result.get("tz.idp.region"));
  }

  @Test
  public void stripsPrefixWhenRequested() {
    Map<String, String> result =
        PrefixedSessionNoteMapperHelper.select(
            notes("tz.idp.department", "security", "tz.idp.region", "emea"), "tz.idp.", true);

    assertEquals(2, result.size());
    assertEquals("security", result.get("department"));
    assertEquals("emea", result.get("region"));
  }

  @Test
  public void skipsExactPrefixMatchWhenStripping() {
    // Key equals the prefix exactly → stripped claim name is empty → skip.
    Map<String, String> result =
        PrefixedSessionNoteMapperHelper.select(notes("tz.idp.", "value"), "tz.idp.", true);

    assertTrue(result.isEmpty());
  }

  @Test
  public void keepsExactPrefixMatchWhenNotStripping() {
    // Edge case: the prefix itself is a valid claim name when we don't strip.
    Map<String, String> result =
        PrefixedSessionNoteMapperHelper.select(notes("tz.idp.", "value"), "tz.idp.", false);

    assertEquals(1, result.size());
    assertEquals("value", result.get("tz.idp."));
  }

  @Test
  public void emptyPrefixSelectsNothing() {
    // We refuse to treat an unconfigured mapper as a "forward everything" match —
    // an empty prefix on a misconfigured instance shouldn't leak every session note.
    Map<String, String> result =
        PrefixedSessionNoteMapperHelper.select(notes("anything", "value"), "", false);

    assertTrue(result.isEmpty());
  }

  @Test
  public void nullNotesReturnsEmpty() {
    Map<String, String> result = PrefixedSessionNoteMapperHelper.select(null, "tz.idp.", false);
    assertTrue(result.isEmpty());
  }

  @Test
  public void skipsNullValues() {
    Map<String, String> source = new HashMap<>();
    source.put("tz.idp.ok", "value");
    source.put("tz.idp.missing", null);

    Map<String, String> result = PrefixedSessionNoteMapperHelper.select(source, "tz.idp.", false);

    assertEquals(1, result.size());
    assertEquals("value", result.get("tz.idp.ok"));
  }

  @Test
  public void preservesInsertionOrderForDeterministicEmission() {
    Map<String, String> result =
        PrefixedSessionNoteMapperHelper.select(
            notes("tz.idp.a", "1", "tz.idp.b", "2", "tz.idp.c", "3"), "tz.idp.", false);

    assertEquals("[tz.idp.a, tz.idp.b, tz.idp.c]", result.keySet().toString());
  }
}
