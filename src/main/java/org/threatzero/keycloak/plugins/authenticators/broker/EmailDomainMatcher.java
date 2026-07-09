package org.threatzero.keycloak.plugins.authenticators.broker;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Pure email-domain matching helper backing {@link
 * IdpAssertedDomainMatchesAuthenticator}. Isolated so the parsing and
 * matching rules can be unit-tested without a Keycloak session.
 */
public final class EmailDomainMatcher {

  private EmailDomainMatcher() {}

  /**
   * Parses a delimited domain list (as stored on an identity provider's
   * config, e.g. {@code "example.com##example.org"}) into a normalized set.
   *
   * <p>Entries are trimmed and lowercased; blank entries are dropped. A null
   * or blank {@code raw} yields an empty set — an identity provider with no
   * configured domains matches nothing.
   *
   * @param raw       delimited domain list; may be null.
   * @param delimiter literal (non-regex) entry separator. Null or empty
   *     treats {@code raw} as a single entry.
   * @return normalized, insertion-ordered set of domains (possibly empty).
   */
  public static Set<String> parseDomains(String raw, String delimiter) {
    Set<String> domains = new LinkedHashSet<>();
    if (raw == null || raw.isBlank()) {
      return domains;
    }
    String[] entries =
        (delimiter == null || delimiter.isEmpty())
            ? new String[] {raw}
            : raw.split(Pattern.quote(delimiter));
    for (String entry : entries) {
      String domain = entry.trim().toLowerCase(Locale.ROOT);
      if (!domain.isEmpty()) {
        domains.add(domain);
      }
    }
    return domains;
  }

  /**
   * Whether {@code email}'s domain is one of {@code domains}.
   *
   * <p>The domain is everything after the last {@code '@'}, compared
   * case-insensitively and <em>exactly</em> — {@code sub.example.com} does
   * not match {@code example.com}. A null/blank email, an email without a
   * domain part, or an empty domain set all yield {@code false}: when in
   * doubt, the caller should fall through to real ownership verification.
   *
   * @param email   asserted email address; may be null.
   * @param domains normalized domain set from {@link #parseDomains}.
   * @return true iff the email's domain is in the set.
   */
  public static boolean matches(String email, Set<String> domains) {
    if (email == null || domains == null || domains.isEmpty()) {
      return false;
    }
    int at = email.lastIndexOf('@');
    if (at < 0 || at == email.length() - 1) {
      return false;
    }
    String domain = email.substring(at + 1).trim().toLowerCase(Locale.ROOT);
    return !domain.isEmpty() && domains.contains(domain);
  }
}
