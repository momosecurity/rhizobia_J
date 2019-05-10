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
 * 
 * This abstract Impl is broken off from the original {@code Codec} class and 
 * provides the {@code Character} parsing logic that has been with ESAPI from the beginning.  
 *
 */
public abstract class AbstractCharacterCodec extends AbstractCodec<Character> {
	/* (non-Javadoc)
	 * @see org.owasp.esapi.codecs.Codec#decode(java.lang.String)
	 */
	@Override
	public String decode(String input) {
		StringBuilder sb = new StringBuilder();
		PushbackSequence<Character> pbs = new PushbackString(input);
		while (pbs.hasNext()) {
			Character c = decodeCharacter(pbs);
			if (c != null) {
				sb.append(c);
			} else {
				sb.append(pbs.next());
			}
		}
		return sb.toString();
	}
}
