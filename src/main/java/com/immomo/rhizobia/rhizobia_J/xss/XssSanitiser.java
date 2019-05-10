/**
 * MOMOSEC Security SDK(MSS)
 *
 * This file is part of the Open MSS Project
 *
 * Copyright (c) 2019 - V0ld1ron
 *
 * The MSS is published by V0ld1ron under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author V0ld1ron (projectone .at. immomo.com)
 * @created 2019
 */
package com.immomo.rhizobia.rhizobia_J.xss;

import com.immomo.rhizobia.rhizobia_J.extra.codecs.HTMLEntityCodec;
import com.immomo.rhizobia.rhizobia_J.extra.codecs.JavaScriptCodec;

/**
 * @program: java安全编码实践
 *
 * @description: 避免xss问题的过滤工具
 *
 * @author: V0ld1ron
 *
 **/
public class XssSanitiser {
    private static XssSanitiser instance = null;
    private final static char[] SAFE_HTML_CHAR     = { ',', '.', '-', '_', ' ' };
    private final static char[] SAFE_HTMLATTR_CAHR = { ',', '.', '-', '_' };
    private final static char[] SAFE_JAVASCRIPT_CHAR = { ',', '.', '_' };

    private static HTMLEntityCodec htmlCodec = null;
    private static JavaScriptCodec javaScriptCodec = null;


    public XssSanitiser() {
        htmlCodec = new HTMLEntityCodec();
        javaScriptCodec = new JavaScriptCodec();
    }

    public static XssSanitiser getInstance() {
        if (null == instance) {
            synchronized (XssSanitiser.class){
                if (null == instance) {
                    instance = new XssSanitiser();
                }
            }
        }
        return instance;
    }

    /**
     * @Description: 过滤输出到html body时的参数，如<body>，<div>，<p>，<td>等等
     *              <body>..input...</body>
     * @Param: input 用于在html body中显示的用户输入
     * @return: String 过滤后的input
     */
    public String encodeForHTML(String input) {
        if( null == input ) {
            return null;
        }
        return htmlCodec.encode(SAFE_HTML_CHAR, input);
    }

    /**
     * @Description: 过滤输出到html body时的参数，如<body>，<div>，<p>，<td>等等
     *              <body>..input...</body>
     * @Param: input 用于在html body中显示的用户输入
     * @return: String 过滤后的input
     */
    public String encodeForHTMLAttribute(String input) {
        if( null == input ) {
            return null;
        }
        return htmlCodec.encode(SAFE_HTMLATTR_CAHR, input);
    }

    /**
     * @Description: 将encode过滤的输入转换回原始输入
     * @Param: input 用于在html body中显示的用户输入
     * @return: String 返回原始输入
     */
    public String decodeForHTML(String input) {
        if( null == input ) {
            return null;
        }
        return htmlCodec.decode(input);
    }

    /**
     * @Description: 过滤输出到JavaScript数据域时的参数，如<script>等等
     *              <script>alert('...input...')</script>
     *              注意：过滤后数据须在引号内，否则仍然是不安全的。
     * @Param: input 用于在JavaScript中显示的用户输入
     * @return: String 过滤后的input
     */
    public String encodeForJavaScript(String input) {
        if( null == input ) {
            return null;
        }
        return javaScriptCodec.encode(SAFE_JAVASCRIPT_CHAR, input);
    }

}
