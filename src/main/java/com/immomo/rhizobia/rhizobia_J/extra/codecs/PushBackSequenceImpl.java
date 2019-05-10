package com.immomo.rhizobia.rhizobia_J.extra.codecs;


/**
 * The pushback string is used by Codecs to allow them to push decoded characters back onto a string
 * for further decoding. This is necessary to detect double-encoding.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class PushBackSequenceImpl extends AbstractPushbackSequence<Integer>{
    /**
     * @param input
     */
    public PushBackSequenceImpl(String input) {
        super(input);
    }

    /**
     * Returns true if the parameter character is a hexidecimal digit 0 through 9, a through f, or A through F.
     *
     * @param c
     * @return
     */
    public static boolean isHexDigit(Integer c) {
        if (c == null) {
            return false;
        }
        Integer ch = Integer.valueOf(c);
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    /**
     * Returns true if the parameter character is an octal digit 0 through 7.
     *
     * @param c
     * @return
     */
    public static boolean isOctalDigit(Integer c) {
        if (c == null) {
            return false;
        }
        Integer ch = Integer.valueOf(c);
        return ch >= '0' && ch <= '7';
    }

    /**
     * @return
     */
    @Override
    public Integer next() {
        if (pushback != null) {
            Integer save = pushback;
            pushback = null;
            return save;
        }
        if (input == null) {
            return null;
        }
        if (input.length() == 0) {
            return null;
        }
        if (index >= input.length()) {
            return null;
        }
        final Integer point = input.codePointAt(index);
        index += Character.charCount(point);
        return point;
    }

    /**
     * @return
     */
    @Override
    public Integer nextHex() {
        Integer c = next();
        if (c == null) {
            return null;
        }
        if (isHexDigit(c)) {
            return c;
        }
        return null;
    }

    /**
     * @return
     */
    @Override
    public Integer nextOctal() {
        Integer c = next();
        if (c == null) {
            return null;
        }
        if (isOctalDigit(c)) {
            return c;
        }
        return null;
    }

    /**
     * Return the next codePoint without affecting the current index.
     *
     * @return
     */
    @Override
    public Integer peek() {
        if (pushback != null) {
            return pushback;
        }
        if (input == null) {
            return null;
        }
        if (input.length() == 0) {
            return null;
        }
        if (index >= input.length()) {
            return null;
        }
        return input.codePointAt(index);
    }

    /**
     * Test to see if the next codePoint is a particular value without affecting the current index.
     *
     * @param c
     * @return
     */
    @Override
    public boolean peek(Integer c) {
        if (pushback != null && pushback.intValue() == c) {
            return true;
        }
        if (input == null) {
            return false;
        }
        if (input.length() == 0) {
            return false;
        }
        if (index >= input.length()) {
            return false;
        }
        return input.codePointAt(index) == c;
    }

    /**
     *
     */
    @Override
    public void mark() {
        temp = pushback;
        mark = index;
    }

    /**
     *
     */
    @Override
    public void reset() {
        pushback = temp;
        index = mark;
    }

    /**
     * @return
     */
    @Override
    public String remainder() {
        String output = input.substring(index);
        if (pushback != null) {
            output = pushback + output;
        }
        return output;
    }

}

