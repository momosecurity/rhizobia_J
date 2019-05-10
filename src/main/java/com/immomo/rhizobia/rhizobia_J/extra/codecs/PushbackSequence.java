/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2017 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Matt Seil (mseil .at. owasp.org)
 * @created 2017
 * 
 */
package com.immomo.rhizobia.rhizobia_J.extra.codecs;;

public interface PushbackSequence<T> {

    /**
     * @param c
     */
    void pushback(T c);

    /**
     * Get the current index of the PushbackString. Typically used in error messages.
     *
     * @return The current index of the PushbackSequence.
     */
    int index();

    /**
     * @return
     */
    boolean hasNext();

    /**
     * @return
     */
    T next();

    /**
     * @return
     */
    T nextHex();

    /**
     * @return
     */
    T nextOctal();

    /**
     * Return the next character without affecting the current index.
     *
     * @return
     */
    T peek();

    /**
     * Test to see if the next character is a particular value without affecting the current index.
     *
     * @param c
     * @return
     */
    boolean peek(T c);

    /**
     *
     */
    void mark();

    /**
     *
     */
    void reset();

    /**
     * Not at all sure what this method is intended to do.  There
     * is a line in HTMLEntityCodec that said calling this method
     * is a "kludge around PushbackString..."
     *
     * @return
     */
    String remainder();

}
