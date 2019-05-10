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
package com.immomo.rhizobia.rhizobia_J.deserialization;

import com.immomo.rhizobia.rhizobia_J.csrf.CSRFTokenUtils;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.InvalidClassException;
import java.util.ArrayList;
import java.util.List;

/**
 * @program: java安全编码实践
 *
 * @description: 安全的反序列化ObjectInputStream方法
 *
 * @author: V0ld1ron
 *
 **/
public class SecureObjectInputStream extends ObjectInputStream {
    private List<String> arrayClassWhiteList = new ArrayList<String>();
    private static Logger logger = Logger.getLogger(CSRFTokenUtils.class);

    public SecureObjectInputStream() throws IOException {
        super();
    }

    public SecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    public SecureObjectInputStream(String[] arrayClassList) throws IOException {
        super();
        for (String x : arrayClassList) {
            if (null == x){
                logger.warn("白名单列表有空值");
                continue;
            }
            arrayClassWhiteList.add(x);
        }
    }

    public SecureObjectInputStream(InputStream in, String[] arrayClassList) throws IOException {
        super(in);
        for (String x : arrayClassList) {
            if (null == x){
                logger.warn("白名单列表有空值");
                continue;
            }
            arrayClassWhiteList.add(x);
        }
    }

    public SecureObjectInputStream(List<String> arrayClassList) throws IOException {
        super();
        for (String x : arrayClassList) {
            if (null == x){
                logger.warn("白名单列表有空值");
                continue;
            }
            arrayClassWhiteList.add(x);
        }
    }

    public SecureObjectInputStream(InputStream in, List<String> arrayClassList) throws IOException {
        super(in);
        for (String x : arrayClassList) {
            if (null == x){
                logger.warn("白名单列表有空值");
                continue;
            }
            arrayClassWhiteList.add(x);
        }
    }

    /**
     * @Description: 校验反序列对象类是否在白名单内
     * @Param: desc 反序列化的类
     * @return: Class 类对象
     */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (0 != this.arrayClassWhiteList.size()) {
            boolean isInWhiteList = false;
            String descName = desc.getName();
            for (String i : this.arrayClassWhiteList) {
                if (i.equals(descName)) {
                    isInWhiteList = true;
                    break;
                }
            }
            if (false == isInWhiteList) {
                logger.error("Unauthorized deserialization class");
                throw new InvalidClassException("Unauthorized deserialization class", desc.getName());
            }
        }
        return super.resolveClass(desc);
    }
}
