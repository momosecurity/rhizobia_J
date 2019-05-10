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

package com.immomo.rhizobia.rhizobia_J.crypto;

import org.apache.commons.codec.digest.DigestUtils;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * @program: java安全编码实践
 *
 * @description: AES 加解密方法
 *               oracle官方已经在如下版本去除了aes-256的限制，6u181，7u171，8u161，9 b148，openjdk7u
 *               https://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8170157
 *
 * @author: V0ld1ron
 *
 **/

public class AESUtils {
    private static AESUtils instance = null;
    private String aesKey = "";
    private String secretKey = "";

    private String iVector = "";
    private String aesMode = "AES/CBC/PKCS5Padding";

    private AESUtils() {

    }

    private AESUtils(String aesKey, String secretKey, String aesMode) {
        this.secretKey = secretKey;
        this.aesKey = DigestUtils.md5Hex(DigestUtils.sha256Hex(aesKey + "|" + secretKey) + "|" + secretKey);
        this.iVector = this.aesKey.substring(8, 24);
        this.aesMode = aesMode == null ? "AES/CBC/PKCS5Padding" : aesMode;
    }

    public static AESUtils getInstance(String aesKey, String secretKey, String aesMode) {
        if (instance == null) {
            synchronized (AESUtils.class) {
                if (null == instance) {
                    instance = new AESUtils(aesKey, secretKey, aesMode);
                }
            }
        } else {
            instance.secretKey = secretKey;
            instance.aesKey = DigestUtils.md5Hex(DigestUtils.sha256Hex(aesKey + "|" + secretKey) + "|" + secretKey);
            instance.iVector = instance.aesKey.substring(8, 24);
            instance.aesMode = aesMode == null ? "AES/CBC/PKCS5Padding" : aesMode;
        }
        return instance;
    }

    public String getaesKey() {
        return aesKey;
    }

    public String getsecretKey() {
        return secretKey;
    }

    public void setiVector(String iVector) {
        this.iVector = iVector;
    }

    public String getaesMode() {
        return aesMode;
    }

    public void setaesMode(String aesMode) {
        this.aesMode = aesMode;
    }

    /**
     * @Description: AES 加密
     * @Param: sSrc 待加密数据
     * @return: byte[] 加密后byte流
     */
    public byte[] encrypt(String sSrc) throws Exception {
        byte[] raw = aesKey.getBytes();
        System.out.println();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance(aesMode);
        IvParameterSpec iv = new IvParameterSpec(iVector.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(sSrc.getBytes());

        return encrypted;
    }

    /**
     * @Description: AES 解密
     * @Param: encrypted 待解密二进制流
     * @return: String 解密后数据
     */
    public String decrypt(byte[] encrypted) throws Exception {
        String originalString = null;
        byte[] raw = aesKey.getBytes("ASCII");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance(aesMode);
        IvParameterSpec iv = new IvParameterSpec(iVector.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] original = cipher.doFinal(encrypted);
        originalString = new String(original);

        return originalString;
    }

}
