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
import com.immomo.rhizobia.rhizobia_J.extra.codecs.DB2Codec;

/**
 * @program: java安全编码实践
 *
 * @description: DB2数据库 sql语句过滤方法
 *
 * @author: V0ld1ron
 *
 **/
public class DB2Sanitiser extends SqliSanitiser {
    private static DB2Sanitiser instance = null;
    Codec DB2Encoder = null;

    public DB2Sanitiser(){
        DB2Encoder = DB2Codec.getInstance();
    }

    public static DB2Sanitiser getInstance() {
        if (null == instance) {
            synchronized (DB2Sanitiser.class) {
                if (null == instance) {
                    instance = new DB2Sanitiser();
                }
            }
        }
        return instance;
    }

    /**
     * @Description: 过滤DB2 sql语句中的特殊字符，暂不支持数据库采用gbk编码
     * @Param: desc 反序列化的类
     * @return: Class 类对象
     */
    public String DB2Sanitise(String input){
        return super.sqlSanitise(DB2Encoder, input);
    }

    /**
     * @Description: 过滤表名、列名的特殊字符，暂不支持数据库采用gbk编码
     * @Param: codec 数据库类型
     * @return: String 过滤后语句
     */
    public String DB2Sanitise(String input, boolean isColumn){
        return super.sqlSanitise(DB2Encoder, input, isColumn);
    }
}
