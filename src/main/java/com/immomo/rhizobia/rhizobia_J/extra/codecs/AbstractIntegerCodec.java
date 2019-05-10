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
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package com.immomo.rhizobia.rhizobia_J.extra.codecs;

/**
 * This class is intended to be an alternative Abstract Implementation for parsing encoding
 * data by focusing on {@code int} as opposed to {@code Character}.  Because non-BMP code
 * points cannot be represented by a {@code char}, this class remedies that by parsing string
 * data as codePoints as opposed to a stream of {@code char}s.
 * 
 * @author Matt Seil (mseil .at. owasp.org)
 * @Created 2017 -- Adapted from Jeff Williams' original {@code Codec} class.  
 */
public class AbstractIntegerCodec extends AbstractCodec<Integer> {

	/**
	 * {@inheritDoc}
	 */
	public String decode(String input) {
		StringBuilder sb = new StringBuilder();
		PushbackSequence<Integer> pbs = new PushBackSequenceImpl(input);
		while (pbs.hasNext()) {
			Integer c = decodeCharacter(pbs);
			boolean isValid = null == c ? false:Character.isValidCodePoint(c);
			if (c != null && isValid) {
				sb.appendCodePoint(c);
			}else{
				sb.appendCodePoint(pbs.next());
			}
		}
		return sb.toString();
	}
}
