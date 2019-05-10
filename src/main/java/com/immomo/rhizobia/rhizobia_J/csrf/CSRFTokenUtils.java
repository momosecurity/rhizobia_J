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
package com.immomo.rhizobia.rhizobia_J.csrf;

import com.immomo.rhizobia.rhizobia_J.extra.commons.EncoderConstants;
import com.immomo.rhizobia.rhizobia_J.extra.commons.RandomCreater;
import org.apache.log4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @program: java安全编码实践
 *
 * @description: CSRF tokent 生成与校验
 *
 * @author: V0ld1ron
 *
 **/

public class CSRFTokenUtils {
    private static CSRFTokenUtils instance = null;
    private static Logger logger = Logger.getLogger(CSRFTokenUtils.class);
    private RandomCreater rc = null;

    private CSRFTokenUtils() throws NoSuchProviderException, NoSuchAlgorithmException {
            rc = new RandomCreater();
    }

   /**
    * @Description: 获取类实例
    * @Param: 无
    * @return: TokenUtils实例
    */
    public static CSRFTokenUtils getInstance() throws NoSuchProviderException, NoSuchAlgorithmException {
        if (null == instance ){
            synchronized (CSRFTokenUtils.class){
                if(null == instance) {
                    instance = new CSRFTokenUtils();
                }
            }
        }
        if (null == instance.rc) {
            throw new RuntimeException("Error creating randomizer Can't find random algorithm SHA1PRNG");
        }
        return instance;
    }

    /**
     * @Description: 返回随机生成的token
     * @Param: length
     * @return: TokenUtils实例
     */
    public String getCsrfToken(int length) {
        if (length <= 0 || length > 10000) {
            logger.warn("长度非法");
            return null;
        }
        String CsrfToken = rc.getRandomString(length, EncoderConstants.CHAR_ALPHANUMERICS);
        return CsrfToken;
    }
}
