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
 * Implementation of the Codec interface for backslash encoding in JavaScript.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class JavaScriptCodec extends AbstractCharacterCodec {


	/**
	 * {@inheritDoc}
	 * 
	 * Returns backslash encoded numeric format. Does not use backslash character escapes
	 * such as, \" or \' as these may cause parsing problems. For example, if a javascript
	 * attribute, such as onmouseover, contains a \" that will close the entire attribute and
	 * allow an attacker to inject another script attribute.
     *
     * @param immune
     */
	public String encodeCharacter(char[] immune, Character c ) {

		// check for immune characters
		if ( containsCharacter(c, immune ) ) {
			return ""+c;
		}
		
		// check for alphanumeric characters
		String hex = super.getHexForNonAlphanumeric(c);
		if ( hex == null ) {
			return ""+c;
		}
				
		// Do not use these shortcuts as they can be used to break out of a context
		// if ( ch == 0x00 ) return "\\0";
		// if ( ch == 0x08 ) return "\\b";
		// if ( ch == 0x09 ) return "\\t";
		// if ( ch == 0x0a ) return "\\n";
		// if ( ch == 0x0b ) return "\\v";
		// if ( ch == 0x0c ) return "\\f";
		// if ( ch == 0x0d ) return "\\r";
		// if ( ch == 0x22 ) return "\\\"";
		// if ( ch == 0x27 ) return "\\'";
		// if ( ch == 0x5c ) return "\\\\";

		// encode up to 256 with \\xHH
        String temp = Integer.toHexString(c);
		if ( c < 256 ) {
	        String pad = "00".substring(temp.length() );
	        return "\\x" + pad + temp.toUpperCase();
		}

		// otherwise encode with \\uHHHH
        String pad = "0000".substring(temp.length() );
        return "\\u" + pad + temp.toUpperCase();
	}

	
	/**
	 * {@inheritDoc}
	 * 
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * See http://www.planetpdf.com/codecuts/pdfs/tutorial/jsspec.pdf 
	 * Formats all are legal both upper/lower case:
	 *   \\a - special characters
	 *   \\xHH
	 *   \\uHHHH
	 *   \\OOO (1, 2, or 3 digits)
	 */
	public Character decodeCharacter(PushbackSequence<Character> input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if (first != '\\' ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		if ( second == null ) {
			input.reset();
			return null;
		}
		
		// \0 collides with the octal decoder and is non-standard
		// if ( second.charValue() == '0' ) {
		//	return Character.valueOf( (char)0x00 );
		if (second == 'b' ) {
			return 0x08;
		} else if (second == 't' ) {
			return 0x09;
		} else if (second == 'n' ) {
			return 0x0a;
		} else if (second == 'v' ) {
			return 0x0b;
		} else if (second == 'f' ) {
			return 0x0c;
		} else if (second == 'r' ) {
			return 0x0d;
		} else if (second == '\"' ) {
			return 0x22;
		} else if (second == '\'' ) {
			return 0x27;
		} else if (second == '\\' ) {
			return 0x5c;
			
		// look for \\xXX format
		} else if ( Character.toLowerCase( second.charValue() ) == 'x' ) {
			// Search for exactly 2 hex digits following
			StringBuilder sb = new StringBuilder();
			for ( int i=0; i<2; i++ ) {
				Character c = input.nextHex();
				if ( c != null ) sb.append( c );
				else {
					input.reset();
					return null;
				}
			}
			try {
				// parse the hex digit and create a character
				int i = Integer.parseInt(sb.toString(), 16);
                if (Character.isValidCodePoint(i)) {
                    return (char) i;
                }
			} catch( NumberFormatException e ) {
				// throw an exception for malformed entity?
				input.reset();
				return null;
			}
			
		// look for \\uXXXX format
		} else if ( Character.toLowerCase( second.charValue() ) == 'u') {
			// Search for exactly 4 hex digits following
			StringBuilder sb = new StringBuilder();
			for ( int i=0; i<4; i++ ) {
				Character c = input.nextHex();
				if ( c != null ) sb.append( c );
				else {
					input.reset();
					return null;
				}
			}
			try {
				// parse the hex string and create a character
				int i = Integer.parseInt(sb.toString(), 16);
                if (Character.isValidCodePoint(i)) {
                    return (char) i;
                }
			} catch( NumberFormatException e ) {
				// throw an exception for malformed entity?
				input.reset();
				return null;
			}
			
		// look for one, two, or three octal digits
		} else if ( PushbackString.isOctalDigit(second) ) {
			StringBuilder sb = new StringBuilder();
            // get digit 1
            sb.append(second);
            
            // get digit 2 if present
            Character c2 = input.next();
            if ( !PushbackString.isOctalDigit(c2) ) {
            	input.pushback( c2 );
            } else {
            	sb.append( c2 );
	            // get digit 3 if present
	            Character c3 = input.next();
	            if ( !PushbackString.isOctalDigit(c3) ) {
	            	input.pushback( c3 );
	            } else {
	            	sb.append( c3 );
	            }
            }
			try {
				// parse the octal string and create a character
				int i = Integer.parseInt(sb.toString(), 8);
                if (Character.isValidCodePoint(i)) {
                    return (char) i;
                }
			} catch( NumberFormatException e ) {
				// throw an exception for malformed entity?
				input.reset();
				return null;
			}
		}
		
		// ignore the backslash and return the character
		return second;
	}

}