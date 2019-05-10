/**
 *
 */
package com.immomo.rhizobia.rhizobia_J.extra.commons;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Neil Matatall (neil.matatall .at. gmail.com)
 * 
 * Are these necessary?  Are there any libraries or java.lang classes to take
 * care of the conversions?
 * 
 * FIXME: we can convert to using this, but it requires that the array be of Character, not char
 *      new HashSet(Arrays.asList(array))
 * 
 */
public class CollectionsUtil {
    private static final char[] EMPTY_CHAR_ARRAY = new char[0];

    /**
     * Private constructor to prevent instantiation.
     */
    private CollectionsUtil() {
    }

    /**
     * Converts an array of chars to a Set of Characters.
     *
     * @param array the contents of the new Set
     * @return a Set containing the elements in the array
     */
    public static Set<Character> arrayToSet(char... array) {
        Set<Character> toReturn;

        if (array == null) {
            return new HashSet<Character>();
        }
        toReturn = new HashSet<Character>(array.length);
        for (char c : array) {
            toReturn.add(c);
        }
        return toReturn;
    }

    /**
     * Convert a char array to a unmodifiable Set.
     *
     * @param array the contents of the new Set
     * @return a unmodifiable Set containing the elements in the
     * array.
     */
    public static Set<Character> arrayToUnmodifiableSet(char... array) {
        if (array == null){
            return Collections.emptySet();
        }
        if (array.length == 1) {
            return Collections.singleton(array[0]);
        }
        return Collections.unmodifiableSet(arrayToSet(array));
    }

    /**
     * Convert a String to a char array
     *
     * @param str The string to convert
     * @return character array containing the characters in str. An
     * empty array is returned if str is null.
     */
    public static char[] strToChars(String str) {
        int len;
        char[] ret;

        if (str == null) {
            return EMPTY_CHAR_ARRAY;
        }
        len = str.length();
        ret = new char[len];
        str.getChars(0, len, ret, 0);
        return ret;
    }

    /**
     * Convert a String to a set of characters.
     *
     * @param str The string to convert
     * @return A set containing the characters in str. A empty set
     * is returned if str is null.
     */
    public static Set<Character> strToSet(String str) {
        Set<Character> set;

        if (str == null){
            return new HashSet<Character>();
        }
        set = new HashSet<Character>(str.length());
        for (int i = 0; i < str.length(); i++){
            set.add(str.charAt(i));
        }
        return set;
    }

    /**
     * Convert a String to a unmodifiable set of characters.
     *
     * @param str The string to convert
     * @return A set containing the characters in str. A empty set
     * is returned if str is null.
     */
    public static Set<Character> strToUnmodifiableSet(String str) {
        if (str == null) {
            return Collections.emptySet();
        }
        if (str.length() == 1) {
            return Collections.singleton(str.charAt(0));
        }
        return Collections.unmodifiableSet(strToSet(str));
    }
}
