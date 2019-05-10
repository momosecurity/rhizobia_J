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
package com.immomo.rhizobia.rhizobia_J.sqli;

import com.immomo.rhizobia.rhizobia_J.base.SqliSanitiser;
import com.immomo.rhizobia.rhizobia_J.extra.codecs.Codec;
import com.immomo.rhizobia.rhizobia_J.extra.codecs.OracleCodec;

/**
 * @program: java安全编码实践
 *
 * @description: Oracle数据库 sql语句过滤方法
 *
 * @author: V0ld1ron
 *
 **/
public class OracleSanitiser extends SqliSanitiser {
    private static OracleSanitiser instance = null;
    Codec oracleEncoder = null;

    public OracleSanitiser(){
        oracleEncoder = OracleCodec.getInstance();
    }

    public static OracleSanitiser getInstance() {
        if (null == instance) {
            synchronized (OracleSanitiser.class) {
                if (null == instance) {
                    instance = new OracleSanitiser();
                }
            }
        }
        return instance;
    }

    /**
     * @Description: 过滤Oracle sql语句中的特殊字符，暂不支持数据库采用gbk编码
     * @Param: desc 反序列化的类
     * @return: Class 类对象
     */
    public String oracleSanitise(String input){
        return super.sqlSanitise(oracleEncoder, input);
    }

    /**
     * @Description: 过滤表名、列名的特殊字符，暂不支持数据库采用gbk编码
     * @Param: codec 数据库类型
     * @return: String 过滤后语句
     */
    public String oracleSanitise(String input, boolean isColumn){
        return super.sqlSanitise(oracleEncoder, input, isColumn);
    }
}
