package org.threatzero.keycloak.plugins.authenticators.broker;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class IdpTrustEmailVerifierAuthenticatorTest {

  @Test
  void verifiesWhenTrustedAndEmailsMatch() {
    assertTrue(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, "amanda@truewestbeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void matchIsCaseInsensitive() {
    assertTrue(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, "Amanda@TrueWestBeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void doesNotVerifyWhenIdpDoesNotTrustEmail() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            false, "amanda@truewestbeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void doesNotVerifyWhenTrustEmailIsNull() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            null, "amanda@truewestbeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void doesNotVerifyWhenBrokeredEmailMissing() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(true, null, "amanda@truewestbeef.com"));
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(true, "  ", "amanda@truewestbeef.com"));
  }

  @Test
  void doesNotVerifyWhenAccountEmailDiffers() {
    // Account was matched on something other than the IdP-asserted email — don't trust it.
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, "amanda@truewestbeef.com", "amanda.barnett@example.org"));
  }

  @Test
  void doesNotVerifyWhenAccountHasNoEmail() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(true, "amanda@truewestbeef.com", null));
  }
}
