package org.threatzero.keycloak.plugins.mappers;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;

class EmailDomainGuardIdpMapperTest {

  private static final Set<String> DOMAINS = Set.of("corp.com", "corp.io");
  private static final boolean EXACT = false;
  private static final boolean SUBDOMAINS = true;

  @Test
  void suppressesOutOfDomainEmailOnUpdatePath() {
    assertTrue(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("attacker@victim.com", DOMAINS, EXACT, true));
  }

  @Test
  void allowsInDomainEmailOnUpdatePath() {
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("alice@corp.com", DOMAINS, EXACT, true));
    assertFalse(EmailDomainGuardIdpMapper.shouldSuppressEmail("bob@corp.io", DOMAINS, EXACT, true));
  }

  @Test
  void neverSuppressesOnFirstBrokerLogin() {
    // No existing link → first broker login → the auth flow owns this, not the mapper.
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail(
            "attacker@victim.com", DOMAINS, EXACT, false));
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("alice@corp.com", DOMAINS, EXACT, false));
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail(
            "attacker@victim.com", DOMAINS, SUBDOMAINS, false));
  }

  @Test
  void passesThroughWhenNoDomainsConfigured() {
    // Without configured domains there is no basis to call an email out-of-domain.
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail(
            "anyone@anywhere.com", Set.of(), EXACT, true));
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("anyone@anywhere.com", null, EXACT, true));
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail(
            "anyone@anywhere.com", Set.of(), SUBDOMAINS, true));
  }

  @Test
  void matchIsCaseInsensitive() {
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("Alice@CORP.COM", DOMAINS, EXACT, true));
    assertTrue(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("Mallory@Victim.COM", DOMAINS, EXACT, true));
  }

  @Test
  void subdomainOfAuthoritativeDomainIsSuppressedInExactMode() {
    // With the flag off, a subdomain the provider hasn't been widened to is out-of-domain.
    assertTrue(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("evil@sub.corp.com", DOMAINS, EXACT, true));
  }

  @Test
  void subdomainOfAuthoritativeDomainIsAllowedWhenMatchingSubdomains() {
    // The provider routes sub.corp.com logins (home.idp.discovery.matchSubdomains), so it may
    // also assert them on the update path.
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail(
            "alice@sub.corp.com", DOMAINS, SUBDOMAINS, true));
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail(
            "alice@deep.sub.corp.io", DOMAINS, SUBDOMAINS, true));
  }

  @Test
  void suffixLookalikeIsStillSuppressedWhenMatchingSubdomains() {
    // Widening to subdomains must not admit "notcorp.com" or a domain merely containing corp.com.
    assertTrue(
        EmailDomainGuardIdpMapper.shouldSuppressEmail(
            "mallory@notcorp.com", DOMAINS, SUBDOMAINS, true));
    assertTrue(
        EmailDomainGuardIdpMapper.shouldSuppressEmail(
            "mallory@corp.com.evil.net", DOMAINS, SUBDOMAINS, true));
  }
}
