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

import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @program: java安全编码实践
 *
 * @description: RSA 加解密方法
 *
 * @author: V0ld1ron
 *
 **/
public class RSAUtils {
    private static RSAUtils instance = null;
    //数字签名 密钥算法
    public String keyAlgorithm = "RSA";
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;

    private RSAUtils() {
    }

    private RSAUtils(String priKeyPath, String pubKeyPath) throws Exception {
        this.privateKey = getPrivateKey(priKeyPath);
        this.publicKey = getPublicKey(pubKeyPath);

    }

    public static RSAUtils getInstance(String priKeyPath, String pubKeyPath) throws Exception {
        if (null == instance) {
            synchronized (RSAUtils.class) {
                if(null == instance) {
                    instance = new RSAUtils(priKeyPath, pubKeyPath);
                }
            }
        } else {
            instance.privateKey = instance.getPrivateKey(priKeyPath);
            instance.publicKey = instance.getPublicKey(pubKeyPath);
        }
        return instance;
    }

    /**
     * @Description: 私钥解密
     * @Param: enData 待解密数据
     * @return: Stirng 解密数据
     */
    public String decrypt(byte[] enData) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] original = cipher.doFinal(enData);
        String originalString = new String(original);
        return originalString;
    }

    /**
     * @Description: 公钥加密
     * @Param: oriData 待加密数据
     * @return: byte[] 加密数据
     */
    public byte[] encrypt(String oriData) throws Exception {
        byte[] data = oriData.getBytes();
        // 对数据加密
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(data);
        return encrypted;
    }

    /**
     * @Description: 签名(私钥加密)
     * @Param: oriData 待签名数据
     * @return: byte[] 数字签名
     */
    public byte[] sign(String oriData) throws Exception {
        byte[] data = oriData.getBytes();
        // 对数据加密
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encrypted = cipher.doFinal(data);
        return encrypted;
    }


    /**
     * @Description: 验签(公钥解密)
     * @Param: sign 签名
     * @return: String 待校验数据
     */
    public String verify(byte[] sign) throws Exception {
        // 对数据解密
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] original = cipher.doFinal(sign);
        String originalString = new String(original);
        return originalString;
    }

    /**
     * @Description: 取得私钥
     * @Param: keyFile 私钥文件路径(pem格式)
     * @return: PrivateKey 私钥
     */
    private PrivateKey getPrivateKey(String keyFile) throws Exception {
        File f = new File(keyFile);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes);
        String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");

        byte[] decoded = new BASE64Decoder().decodeBuffer(privKeyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm);
        return kf.generatePrivate(spec);
    }

    /**
     * @Description: 取得公钥
     * @Param: keyFile 公钥文件路径(pem格式)
     * @return: PublicKey 公钥
     */
    private PublicKey getPublicKey(String keyFile) throws Exception {
        File f = new File(keyFile);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes);
        String publicKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");

        byte[] decoded = new BASE64Decoder().decodeBuffer(publicKeyPEM);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm);
        return kf.generatePublic(spec);
    }

}
