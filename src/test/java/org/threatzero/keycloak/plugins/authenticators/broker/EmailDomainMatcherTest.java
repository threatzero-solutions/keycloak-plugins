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
  public void parseMatchSubdomainsAcceptsOnlyTrue() {
    assertTrue(EmailDomainMatcher.parseMatchSubdomains("true"));
    assertTrue(EmailDomainMatcher.parseMatchSubdomains("TRUE"));
    assertTrue(EmailDomainMatcher.parseMatchSubdomains("  true "));
    assertFalse(EmailDomainMatcher.parseMatchSubdomains("false"));
    assertFalse(EmailDomainMatcher.parseMatchSubdomains("yes"));
    assertFalse(EmailDomainMatcher.parseMatchSubdomains("1"));
    assertFalse(EmailDomainMatcher.parseMatchSubdomains(""));
    assertFalse(EmailDomainMatcher.parseMatchSubdomains(null));
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
  public void subdomainDoesNotMatchParentDomainByDefault() {
    // Exact mode (the two-arg overload, and the flag off) never widens in either direction.
    assertFalse(EmailDomainMatcher.matches("alice@sub.example.com", Set.of("example.com")));
    assertFalse(EmailDomainMatcher.matches("alice@sub.example.com", Set.of("example.com"), false));
    assertFalse(EmailDomainMatcher.matches("alice@example.com", Set.of("sub.example.com")));
  }

  @Test
  public void matchSubdomainsAcceptsAnyDepthUnderAConfiguredDomain() {
    Set<String> domains = Set.of("example.com");
    assertTrue(EmailDomainMatcher.matches("alice@sub.example.com", domains, true));
    assertTrue(EmailDomainMatcher.matches("alice@deep.sub.example.com", domains, true));
    assertTrue(EmailDomainMatcher.matches("Alice@SUB.Example.COM", domains, true));
  }

  @Test
  public void matchSubdomainsStillAcceptsTheConfiguredDomainItself() {
    assertTrue(EmailDomainMatcher.matches("alice@example.com", Set.of("example.com"), true));
  }

  @Test
  public void matchSubdomainsRejectsSuffixLookalikes() {
    // The separator dot is part of the rule: "notexample.com" is not under "example.com".
    Set<String> domains = Set.of("example.com");
    assertFalse(EmailDomainMatcher.matches("mallory@notexample.com", domains, true));
    assertFalse(EmailDomainMatcher.matches("mallory@example.com.evil.net", domains, true));
  }

  @Test
  public void matchSubdomainsNeverWidensAConfiguredSubdomainToItsParent() {
    // Only descendants of a configured domain match — never its ancestors or siblings.
    Set<String> domains = Set.of("sub.example.com");
    assertFalse(EmailDomainMatcher.matches("alice@example.com", domains, true));
    assertFalse(EmailDomainMatcher.matches("alice@other.example.com", domains, true));
    assertTrue(EmailDomainMatcher.matches("alice@deep.sub.example.com", domains, true));
  }

  @Test
  public void emptyDomainSetMatchesNothing() {
    assertFalse(EmailDomainMatcher.matches("alice@example.com", Set.of()));
    assertFalse(EmailDomainMatcher.matches("alice@example.com", null));
    assertFalse(EmailDomainMatcher.matches("alice@sub.example.com", Set.of(), true));
    assertFalse(EmailDomainMatcher.matches("alice@sub.example.com", null, true));
  }

  @Test
  public void rejectsMalformedEmails() {
    Set<String> domains = Set.of("example.com");
    assertFalse(EmailDomainMatcher.matches(null, domains));
    assertFalse(EmailDomainMatcher.matches("", domains));
    assertFalse(EmailDomainMatcher.matches("no-at-sign", domains));
    assertFalse(EmailDomainMatcher.matches("trailing-at@", domains));
    assertFalse(EmailDomainMatcher.matches("example.com", domains));
    assertFalse(EmailDomainMatcher.matches("trailing-at@", domains, true));
  }

  @Test
  public void domainAfterLastAtSignWins() {
    // Quoted local parts may themselves contain '@'; only the last one delimits the domain.
    assertTrue(EmailDomainMatcher.matches("\"weird@local\"@example.com", Set.of("example.com")));
    assertFalse(EmailDomainMatcher.matches("alice@example.com@evil.net", Set.of("example.com")));
    assertFalse(
        EmailDomainMatcher.matches("alice@example.com@evil.net", Set.of("example.com"), true));
  }
}
