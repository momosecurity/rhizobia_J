/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package com.immomo.rhizobia.rhizobia_J.extra.codecs;



/**
 * Implementation of the Codec interface for MySQL strings. See http://mirror.yandex.ru/mirrors/ftp.mysql.com/doc/refman/5.0/en/string-syntax.html
 * for more information.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class MySQLCodec extends AbstractCharacterCodec {

    /**
     * Target MySQL Server is running in Standard MySQL (Default) mode.
     */
    public static final int MYSQL_MODE = 0;
    /**
     * Target MySQL Server is running in {@link "http://dev.mysql.com/doc/refman/5.0/en/ansi-mode.html"} ANSI Mode
     */
    public static final int ANSI_MODE = 1;
    private static MySQLCodec instance = new MySQLCodec();
    //private int mode = 0;
    private Mode mode = Mode.STANDARD;
    /**
     * Instantiate the MySQL codec
     *
     * @param mode Mode has to be one of {MYSQL_MODE|ANSI_MODE} to allow correct encoding
     */
    private MySQLCodec(int mode) {
        this.mode = Mode.findByKey(mode);
    }

    /**
     * Instantiate the MySQL Codec with the given SQL {@link Mode}.
     *
     * @param mode The mode the target server is running in
     */
    private MySQLCodec(Mode mode) {
        this.mode = mode;
    }

    private MySQLCodec() {

    }

    public static MySQLCodec getInstance() {
        return instance;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns quote-encoded character
     *
     * @param immune
     */
    @Override
    public String encodeCharacter(char[] immune, Character c) {
        char ch = c.charValue();

        // check for immune characters
        if (containsCharacter(ch, immune)) {
            return "" + ch;
        }

        // check for alphanumeric characters
        String hex = super.getHexForNonAlphanumeric(ch);
        if (hex == null) {
            return "" + ch;
        }

        switch (mode) {
            case ANSI:
                return encodeCharacterANSI(c);
            case STANDARD:
                return encodeCharacterMySQL(c);
            default:
                ;
        }
        return null;
    }

    /**
     * encodeCharacterANSI encodes for ANSI SQL.
     * <p>
     * Apostrophe is encoded
     * <p>
     * Bug ###: In ANSI Mode Strings can also be passed in using the quotation. In ANSI_QUOTES mode a quotation
     * is considered to be an identifier, thus cannot be used at all in a value and will be dropped completely.
     *
     * @param c character to encode
     * @return String encoded to standards of MySQL running in ANSI mode
     */
    private String encodeCharacterANSI(Character c) {
        if (c == '\'') {
            return "\'\'";
        }
        if (c == '\"') {
            return "";
        }
        return "" + c;
    }

    /**
     * Encode a character suitable for MySQL
     *
     * @param c Character to encode
     * @return Encoded Character
     */
    private String encodeCharacterMySQL(Character c) {
        char ch = c.charValue();
        if (ch == 0x00) {
            return "\\0";
        }
        if (ch == 0x08) {
            return "\\b";
        }
        if (ch == 0x09) {
            return "\\t";
        }
        if (ch == 0x0a) {
            return "\\n";
        }
        if (ch == 0x0d) {
            return "\\r";
        }
        if (ch == 0x1a) {
            return "\\Z";
        }
        if (ch == 0x22) {
            return "\\\"";
        }
        if (ch == 0x25) {
            return "\\%";
        }
        if (ch == 0x27) {
            return "\\'";
        }
        if (ch == 0x5c) {
            return "\\\\";
        }
        if (ch == 0x5f) {
            return "\\_";
        }
        return "\\" + c;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns the decoded version of the character starting at index, or
     * null if no decoding is possible.
     * <p>
     * Formats all are legal (case sensitive)
     * In ANSI_MODE '' decodes to '
     * In MYSQL_MODE \x decodes to x (or a small list of specials)
     */
    @Override
    public Character decodeCharacter(PushbackSequence<Character> input) {
        switch (mode) {
            case ANSI:
                return decodeCharacterANSI(input);
            case STANDARD:
                return decodeCharacterMySQL(input);
            default:
                ;
        }
        return null;
    }

    /**
     * decodeCharacterANSI decodes the next character from ANSI SQL escaping
     *
     * @param input A PushBackString containing characters you'd like decoded
     * @return A single character, decoded
     */
    private Character decodeCharacterANSI(PushbackSequence<Character> input) {
        input.mark();
        Character first = input.next();
        if (first == null) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if (first.charValue() != '\'') {
            input.reset();
            return null;
        }

        Character second = input.next();
        if (second == null) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if (second.charValue() != '\'') {
            input.reset();
            return null;
        }
        return (Character.valueOf('\''));
    }

    /**
     * decodeCharacterMySQL decodes all the potential escaped characters that MySQL is prepared to escape
     *
     * @param input A string you'd like to be decoded
     * @return A single character from that string, decoded.
     */
    private Character decodeCharacterMySQL(PushbackSequence<Character> input) {
        input.mark();
        Character first = input.next();
        if (first == null) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if (first.charValue() != '\\') {
            input.reset();
            return null;
        }

        Character second = input.next();
        if (second == null) {
            input.reset();
            return null;
        }

        if (second.charValue() == '0') {
            return Character.valueOf((char) 0x00);
        } else if (second.charValue() == 'b') {
            return Character.valueOf((char) 0x08);
        } else if (second.charValue() == 't') {
            return Character.valueOf((char) 0x09);
        } else if (second.charValue() == 'n') {
            return Character.valueOf((char) 0x0a);
        } else if (second.charValue() == 'r') {
            return Character.valueOf((char) 0x0d);
        } else if (second.charValue() == 'z') {
            return Character.valueOf((char) 0x1a);
        } else if (second.charValue() == '\"') {
            return Character.valueOf((char) 0x22);
        } else if (second.charValue() == '%') {
            return Character.valueOf((char) 0x25);
        } else if (second.charValue() == '\'') {
            return Character.valueOf((char) 0x27);
        } else if (second.charValue() == '\\') {
            return Character.valueOf((char) 0x5c);
        } else if (second.charValue() == '_') {
            return Character.valueOf((char) 0x5f);
        } else {
            return second;
        }
    }

    /**
     * Currently the only supported modes are:
     * ANSI
     * STANDARD
     */
    public static enum Mode {
        ANSI(1), STANDARD(0);

        private int key;

        private Mode(int key) {
            this.key = key;
        }

        static Mode findByKey(int key) {
            for (Mode m : values()) {
                if (m.key == key) {
                    return m;
                }
            }
            return null;
        }
    }

}