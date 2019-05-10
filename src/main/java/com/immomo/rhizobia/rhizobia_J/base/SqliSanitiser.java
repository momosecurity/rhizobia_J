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
package com.immomo.rhizobia.rhizobia_J.base;
import com.immomo.rhizobia.rhizobia_J.extra.codecs.Codec;

/**
 * @program: java安全编码实践
 *
 * @description: sql语句过滤方法
 *
 * @author: V0ld1ron
 *
 **/
public class SqliSanitiser {
    private final static char[] SAFE_SQL_CHAR = {' '};
    private final static char[] SAFE_SQL_CHAR_COLUMN = {' ', '_', '$'};

    public SqliSanitiser(){

    }

    /**
     * @Description: 过滤sql语句中的特殊字符，暂不支持数据库采用gbk编码
     * @Param: desc 反序列化的类
     * @return: Class 类对象
     */
    protected String sqlSanitise(Codec codec, String input) {
        if (null == input) {
            return null;
        }
        return codec.encode(SAFE_SQL_CHAR, input);
    }

    /**
     * @Description: 过滤表名、列名的特殊字符，暂不支持数据库采用gbk编码
     * @Param: codec 数据库类型
     * @return: String 过滤后语句
     */
    protected String sqlSanitise(Codec codec, String input, boolean isColumn) {
        if (null == input) {
            return null;
        }
        if (isColumn) {
            return codec.encode(SAFE_SQL_CHAR_COLUMN, input);
        } else {
            return codec.encode(SAFE_SQL_CHAR, input);
        }
    }
}
