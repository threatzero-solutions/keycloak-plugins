package org.threatzero.keycloak.plugins.mappers;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;

class EmailDomainGuardIdpMapperTest {

  private static final Set<String> DOMAINS = Set.of("corp.com", "corp.io");

  @Test
  void suppressesOutOfDomainEmailOnUpdatePath() {
    assertTrue(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("attacker@victim.com", DOMAINS, true));
  }

  @Test
  void allowsInDomainEmailOnUpdatePath() {
    assertFalse(EmailDomainGuardIdpMapper.shouldSuppressEmail("alice@corp.com", DOMAINS, true));
    assertFalse(EmailDomainGuardIdpMapper.shouldSuppressEmail("bob@corp.io", DOMAINS, true));
  }

  @Test
  void neverSuppressesOnFirstBrokerLogin() {
    // No existing link → first broker login → the auth flow owns this, not the mapper.
    assertFalse(
        EmailDomainGuardIdpMapper.shouldSuppressEmail("attacker@victim.com", DOMAINS, false));
    assertFalse(EmailDomainGuardIdpMapper.shouldSuppressEmail("alice@corp.com", DOMAINS, false));
  }

  @Test
  void passesThroughWhenNoDomainsConfigured() {
    // Without configured domains there is no basis to call an email out-of-domain.
    assertFalse(EmailDomainGuardIdpMapper.shouldSuppressEmail("anyone@anywhere.com", Set.of(), true));
    assertFalse(EmailDomainGuardIdpMapper.shouldSuppressEmail("anyone@anywhere.com", null, true));
  }

  @Test
  void matchIsCaseInsensitive() {
    assertFalse(EmailDomainGuardIdpMapper.shouldSuppressEmail("Alice@CORP.COM", DOMAINS, true));
    assertTrue(EmailDomainGuardIdpMapper.shouldSuppressEmail("Mallory@Victim.COM", DOMAINS, true));
  }

  @Test
  void subdomainOfAuthoritativeDomainIsSuppressed() {
    // Exact-domain match only: a lookalike subdomain the provider doesn't own is out-of-domain.
    assertTrue(EmailDomainGuardIdpMapper.shouldSuppressEmail("evil@sub.corp.com", DOMAINS, true));
  }
}
