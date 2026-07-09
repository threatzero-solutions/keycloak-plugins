package org.threatzero.keycloak.plugins.authenticators.broker;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class IdpTrustEmailVerifierAuthenticatorTest {

  @Test
  void verifiesWhenTrustedAndEmailsMatch() {
    assertTrue(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, false, "amanda@truewestbeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void matchIsCaseInsensitive() {
    assertTrue(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, false, "Amanda@TrueWestBeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void doesNotVerifyWhenIdpDoesNotTrustEmail() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            false, false, "amanda@truewestbeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void doesNotVerifyWhenTrustEmailIsNull() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            null, false, "amanda@truewestbeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void alwaysTrustVerifiesWithoutTrustEmail() {
    // A preceding flow condition vouches for the broker — trustEmail may be off or unset.
    assertTrue(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            false, true, "amanda@truewestbeef.com", "amanda@truewestbeef.com"));
    assertTrue(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            null, true, "amanda@truewestbeef.com", "amanda@truewestbeef.com"));
  }

  @Test
  void alwaysTrustStillRequiresMatchingEmail() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            false, true, "amanda@truewestbeef.com", "amanda.barnett@example.org"));
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            false, true, null, "amanda@truewestbeef.com"));
  }

  @Test
  void doesNotVerifyWhenBrokeredEmailMissing() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, false, null, "amanda@truewestbeef.com"));
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, false, "  ", "amanda@truewestbeef.com"));
  }

  @Test
  void doesNotVerifyWhenAccountEmailDiffers() {
    // Account was matched on something other than the IdP-asserted email — don't trust it.
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, false, "amanda@truewestbeef.com", "amanda.barnett@example.org"));
  }

  @Test
  void doesNotVerifyWhenAccountHasNoEmail() {
    assertFalse(
        IdpTrustEmailVerifierAuthenticator.shouldVerifyEmail(
            true, false, "amanda@truewestbeef.com", null));
  }
}
