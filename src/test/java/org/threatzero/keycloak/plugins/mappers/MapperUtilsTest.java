package org.threatzero.keycloak.plugins.mappers;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class MapperUtilsTest {

  @Test
  public void testGlobToRegex_singleStar() {
    String glob = "*.txt";
    String expectedRegex = "^[^/]*\\.txt$";
    assertEquals(expectedRegex, MapperUtils.globToRegex(glob));
  }

  @Test
  public void testGlobToRegex_doubleStar() {
    String glob = "**/*.txt";
    String expectedRegex = "^.*/[^/]*\\.txt$";
    assertEquals(expectedRegex, MapperUtils.globToRegex(glob));
  }

  @Test
  public void testGlobToRegex_questionMark() {
    String glob = "file?.txt";
    String expectedRegex = "^file.\\.txt$";
    assertEquals(expectedRegex, MapperUtils.globToRegex(glob));
  }

  @Test
  public void testGlobToRegex_specialCharacters() {
    String glob = "file[abc].txt";
    String expectedRegex = "^file\\[abc\\]\\.txt$";
    assertEquals(expectedRegex, MapperUtils.globToRegex(glob));
  }

  @Test
  public void testMatchesGlob_match() {
    String glob = "*.txt";
    String value = "test.txt";
    assertTrue(MapperUtils.matchesGlob(glob, value));
  }

  @Test
  public void testMatchesGlob_noMatch() {
    String glob = "*.txt";
    String value = "test.jpg";
    assertFalse(MapperUtils.matchesGlob(glob, value));
  }

  @Test
  public void testMatchesGlob_doubleStarMatch() {
    String glob = "**/test.txt";
    String value = "some/path/to/test.txt";
    assertTrue(MapperUtils.matchesGlob(glob, value));
  }

  @Test
  public void testMatchesGlob_questionMarkMatch() {
    String glob = "file?.txt";
    String value = "file1.txt";
    assertTrue(MapperUtils.matchesGlob(glob, value));
  }

  @Test
  public void testMatchesGlob_questionMarkNoMatch() {
    String glob = "file?.txt";
    String value = "file10.txt";
    assertFalse(MapperUtils.matchesGlob(glob, value));
  }
}
