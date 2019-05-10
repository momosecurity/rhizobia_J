package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.xss.XssSanitiser;
import org.junit.Test;

import static org.junit.Assert.*;

public class XssEncoderTest {

    private XssSanitiser xssFilter = XssSanitiser.getInstance();
    @Test
    public void encodeForHTML() {
        String oriString = "data 1 2";
        String ret = xssFilter.encodeForHTML(oriString);
        assertTrue(ret.equals(oriString));
        System.out.println(ret);
        ret = xssFilter.decodeForHTML(ret);
        assertTrue(ret.equals(oriString));
        System.out.println(ret);

        oriString = "<script>alert('xss')</script>";
        ret = xssFilter.encodeForHTML(oriString);
        assertFalse(ret.equals(oriString));
        System.out.println(ret);
        ret = xssFilter.decodeForHTML(ret);
        assertTrue(ret.equals(oriString));
        System.out.println(ret);

        oriString = "data 1 2";
        ret = xssFilter.encodeForHTMLAttribute(oriString);
        assertFalse(ret.equals(oriString));
        System.out.println(ret);
        ret = xssFilter.decodeForHTML(ret);
        assertTrue(ret.equals(oriString));
        System.out.println(ret);

        oriString = "<script>alert('xss')</script>";
        ret = xssFilter.encodeForHTMLAttribute(oriString);
        assertFalse(ret.equals(oriString));
        System.out.println(ret);
        ret = xssFilter.decodeForHTML(ret);
        assertTrue(ret.equals(oriString));
        System.out.println(ret);

        oriString = "'}});}}});alert(1);</script>";
        ret = xssFilter.encodeForJavaScript(oriString);
        assertFalse(ret.equals(oriString));
        System.out.println(ret);

    }

    @Test
    public void decodeForHTML() {
    }
}