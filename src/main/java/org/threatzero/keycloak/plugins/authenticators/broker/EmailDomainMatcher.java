package org.threatzero.keycloak.plugins.authenticators.broker;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Pure email-domain matching helper backing {@link IdpAssertedDomainMatchesAuthenticator} and
 * the email-domain-guard identity-provider mapper. Isolated so the parsing and matching rules
 * can be unit-tested without a Keycloak session.
 *
 * <p>Matching deliberately mirrors the home-IdP-discovery routing plugin
 * (sventorben/keycloak-home-idp-discovery), so a login that plugin routed to a provider is
 * judged in-domain here by the same rule: an exact match always, and — when the provider's
 * {@code home.idp.discovery.matchSubdomains} flag is on — any subdomain of a configured domain
 * as well.
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
   * Parses the subdomain-matching flag as stored on an identity provider's config (the
   * home-IdP-discovery plugin's {@code home.idp.discovery.matchSubdomains}).
   *
   * <p>Only a trimmed, case-insensitive {@code "true"} enables it. Null, blank, or anything
   * else is {@code false} — the plugin's own default, so an unset flag keeps exact matching.
   *
   * @param raw the config attribute value; may be null.
   * @return whether subdomains of the configured domains should also match.
   */
  public static boolean parseMatchSubdomains(String raw) {
    return raw != null && raw.trim().equalsIgnoreCase("true");
  }

  /**
   * Whether {@code email}'s domain is one of {@code domains}, compared exactly. Equivalent to
   * {@link #matches(String, Set, boolean)} with subdomain matching off.
   *
   * @param email   asserted email address; may be null.
   * @param domains normalized domain set from {@link #parseDomains}.
   * @return true iff the email's domain is in the set.
   */
  public static boolean matches(String email, Set<String> domains) {
    return matches(email, domains, false);
  }

  /**
   * Whether {@code email}'s domain is one of {@code domains}, or — with {@code
   * matchSubdomains} — a subdomain of one.
   *
   * <p>The domain is everything after the last {@code '@'}, compared case-insensitively. An
   * exact match is tried first. With {@code matchSubdomains}, {@code sub.example.com} and
   * {@code deep.sub.example.com} also match a configured {@code example.com}: the same
   * dot-delimited suffix rule the home-IdP-discovery plugin routes by. Because the separator
   * dot is part of the test, a lookalike such as {@code notexample.com} never matches, and a
   * configured {@code sub.example.com} never widens to its parent.
   *
   * <p>A null/blank email, an email without a domain part, or an empty domain set all yield
   * {@code false}: when in doubt, the caller should fall through to real ownership
   * verification.
   *
   * @param email           asserted email address; may be null.
   * @param domains         normalized domain set from {@link #parseDomains}.
   * @param matchSubdomains whether a subdomain of a configured domain also matches.
   * @return true iff the email's domain matches under the selected rule.
   */
  public static boolean matches(String email, Set<String> domains, boolean matchSubdomains) {
    if (email == null || domains == null || domains.isEmpty()) {
      return false;
    }
    int at = email.lastIndexOf('@');
    if (at < 0 || at == email.length() - 1) {
      return false;
    }
    String domain = email.substring(at + 1).trim().toLowerCase(Locale.ROOT);
    if (domain.isEmpty()) {
      return false;
    }
    if (domains.contains(domain)) {
      return true;
    }
    // Subdomain rule: a configured domain matches as a dot-delimited suffix. Keeping the dot
    // in the test is what stops "notexample.com" from matching "example.com".
    return matchSubdomains && domains.stream().anyMatch(d -> domain.endsWith("." + d));
  }
}
