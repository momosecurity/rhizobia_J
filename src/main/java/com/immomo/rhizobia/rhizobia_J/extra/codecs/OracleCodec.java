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
 * Implementation of the Codec interface for Oracle strings. This function will only protect you from SQLi in the case of user data
 * bring placed within an Oracle quoted string such as:
 * 
 * select * from table where user_name='  USERDATA    ';
 * 
 * @see <a href="http://oraqa.com/2006/03/20/how-to-escape-single-quotes-in-strings/">how-to-escape-single-quotes-in-strings</a>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class OracleCodec extends AbstractCharacterCodec {

    private static OracleCodec instance = new OracleCodec();

    private OracleCodec() {
    }

    ;

    public static OracleCodec getInstance() {
        return instance;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Encodes ' to ''
     * <p>
     * Encodes ' to ''
     *
     * @param immune
     */
    @Override
    public String encodeCharacter(char[] immune, Character c) {
        if (c.charValue() == '\'') {
            return "\'\'";
        }
        return "" + c;
    }


    /**
     * {@inheritDoc}
     * <p>
     * Returns the decoded version of the character starting at index, or
     * null if no decoding is possible.
     * <p>
     * Formats all are legal
     * '' decodes to '
     */
    @Override
    public Character decodeCharacter(PushbackSequence<Character> input) {
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

}