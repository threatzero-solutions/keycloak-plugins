package org.threatzero.keycloak.plugins.mappers;

public class MapperUtils {
  public static boolean matchesGlob(String glob, String value) {
    return value.matches(globToRegex(glob));
  }

  public static String globToRegex(String glob) {
    StringBuilder regex = new StringBuilder("^");

    for (int i = 0; i < glob.length(); i++) {
      char c = glob.charAt(i);
      switch (c) {
        case '*':
          if (i + 1 < glob.length() && glob.charAt(i + 1) == '*') {
            // Handle '**' for matching the rest of the path
            regex.append(".*");
            i++; // Skip the next '*'
          } else {
            // Handle '*' for matching a single path segment
            regex.append("[^/]*");
          }
          break;
        case '?':
          // Handle '?' for matching any single character
          regex.append(".");
          break;
        case '.':
        case '\\':
        case '+':
        case '^':
        case '$':
        case '[':
        case ']':
        case '(':
        case ')':
        case '{':
        case '}':
        case '|':
          // Escape regex special characters
          regex.append("\\").append(c);
          break;
        default:
          // Append regular characters
          regex.append(c);
          break;
      }
    }

    regex.append("$");
    return regex.toString();
  }
}
