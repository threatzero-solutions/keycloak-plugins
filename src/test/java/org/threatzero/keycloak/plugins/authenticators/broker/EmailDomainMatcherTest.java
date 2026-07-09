package org.threatzero.keycloak.plugins.authenticators.broker;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

public class EmailDomainMatcherTest {

  private static final String DELIM = "##";

  @Test
  public void parsesDelimitedDomains() {
    Set<String> domains = EmailDomainMatcher.parseDomains("example.com##example.org", DELIM);
    assertEquals(List.of("example.com", "example.org"), List.copyOf(domains));
  }

  @Test
  public void parseNormalizesCaseAndWhitespaceAndDropsBlanks() {
    Set<String> domains =
        EmailDomainMatcher.parseDomains("  Example.COM ##   ## example.com ", DELIM);
    assertEquals(Set.of("example.com"), domains);
  }

  @Test
  public void parseOfNullOrBlankYieldsEmptySet() {
    assertTrue(EmailDomainMatcher.parseDomains(null, DELIM).isEmpty());
    assertTrue(EmailDomainMatcher.parseDomains("", DELIM).isEmpty());
    assertTrue(EmailDomainMatcher.parseDomains("   ", DELIM).isEmpty());
  }

  @Test
  public void parseWithNullOrEmptyDelimiterTreatsRawAsSingleEntry() {
    assertEquals(
        Set.of("example.com##example.org"),
        EmailDomainMatcher.parseDomains("example.com##example.org", null));
    assertEquals(Set.of("example.com"), EmailDomainMatcher.parseDomains(" Example.com ", ""));
  }

  @Test
  public void parseDelimiterIsLiteralNotRegex() {
    // A regex-special delimiter must not be interpreted as a pattern.
    Set<String> domains = EmailDomainMatcher.parseDomains("example.com|example.org", "|");
    assertEquals(Set.of("example.com", "example.org"), domains);
  }

  @Test
  public void matchesInDomainEmail() {
    Set<String> domains = Set.of("example.com", "example.org");
    assertTrue(EmailDomainMatcher.matches("alice@example.com", domains));
    assertTrue(EmailDomainMatcher.matches("bob@example.org", domains));
  }

  @Test
  public void matchIsCaseInsensitive() {
    assertTrue(EmailDomainMatcher.matches("Alice@EXAMPLE.COM", Set.of("example.com")));
  }

  @Test
  public void rejectsOutOfDomainEmail() {
    assertFalse(EmailDomainMatcher.matches("mallory@evil.example.net", Set.of("example.com")));
  }

  @Test
  public void subdomainDoesNotMatchParentDomain() {
    assertFalse(EmailDomainMatcher.matches("alice@sub.example.com", Set.of("example.com")));
    assertFalse(EmailDomainMatcher.matches("alice@example.com", Set.of("sub.example.com")));
  }

  @Test
  public void emptyDomainSetMatchesNothing() {
    assertFalse(EmailDomainMatcher.matches("alice@example.com", Set.of()));
    assertFalse(EmailDomainMatcher.matches("alice@example.com", null));
  }

  @Test
  public void rejectsMalformedEmails() {
    Set<String> domains = Set.of("example.com");
    assertFalse(EmailDomainMatcher.matches(null, domains));
    assertFalse(EmailDomainMatcher.matches("", domains));
    assertFalse(EmailDomainMatcher.matches("no-at-sign", domains));
    assertFalse(EmailDomainMatcher.matches("trailing-at@", domains));
    assertFalse(EmailDomainMatcher.matches("example.com", domains));
  }

  @Test
  public void domainAfterLastAtSignWins() {
    // Quoted local parts may themselves contain '@'; only the last one delimits the domain.
    assertTrue(EmailDomainMatcher.matches("\"weird@local\"@example.com", Set.of("example.com")));
    assertFalse(EmailDomainMatcher.matches("alice@example.com@evil.net", Set.of("example.com")));
  }
}
