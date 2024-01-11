package dev.emad.utils;

import org.springframework.lang.Nullable;

/**
 * @author EmadHanif
 */
public class StringHelper {

  public static String changeFirstCharacterCase(String str, boolean capitalize) {

    if (!hasLength(str)) return str;

    char firstChar = str.charAt(0);

    if (!Character.isLetter(firstChar)) {
      return str;
    }
    char updatedChar =
        capitalize ? Character.toUpperCase(firstChar) : Character.toLowerCase(firstChar);

    // May be unnecessary, but brings slight optimization...
    if (firstChar == updatedChar) {
      return str;
    } else if (str.length() == 1) {
      return String.valueOf(updatedChar);
    } else {
      StringBuilder stringBuilder = new StringBuilder(str);
      stringBuilder.setCharAt(0, updatedChar);
      return stringBuilder.toString();
    }
  }

  public static boolean hasLength(@Nullable String str) {
    return str != null && !str.isEmpty();
  }

  public static boolean hasText(@Nullable String str) {
    return str != null && !str.isBlank();
  }
}
