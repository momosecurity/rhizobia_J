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
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @program: java安全编码实践
 *
 * @description: RSA 加解密方法
 *
 * 知识点2：之所以没有用base64或16进制处理加密后的内容，是因为在使用base64编码后的内容中，可能存在'+'字符，
 *         '+'字符返回给前端后再返回给后端时，如果不经过处理，会变为' '空格字符，
 *         所以在对加密内容进行base64编码时，请注意'+'字符
 *
 * @author: V0ld1ron
 *>
 * @issue: 感谢LeadroyaL[issue](https://github.com/momosecurity/rhizobia_J/issues/1)
 **/
public class RSAUtils {
    private static RSAUtils instance = null;

    //数字签名 密钥算法
    private String keyAlgorithm = "RSA";
    private String encryptAlgorithm = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private String signatureAlgorithm = "SHA1withRSA";
    private String pemPriHead = "-----BEGIN PRIVATE KEY-----\n";
    private String pemPriEnd = "-----END PRIVATE KEY-----";
    private String pemPubHead = "-----BEGIN PUBLIC KEY-----\n";
    private String pemPubEnd = "-----END PUBLIC KEY-----";

    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getEncryptAlgorithm() {
        return encryptAlgorithm;
    }

    public void setEncryptAlgorithm(String encryptAlgorithm) {
        this.encryptAlgorithm = encryptAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getPemPriHead() {
        return pemPriHead;
    }

    public void setPemPriHead(String pemPriHead) {
        this.pemPriHead = pemPriHead;
    }

    public String getPemPriEnd() {
        return pemPriEnd;
    }

    public void setPemPriEnd(String pemPriEnd) {
        this.pemPriEnd = pemPriEnd;
    }

    public String getPemPubHead() {
        return pemPubHead;
    }

    public void setPemPubHead(String pemPubHead) {
        this.pemPubHead = pemPubHead;
    }

    public String getPemPubEnd() {
        return pemPubEnd;
    }

    public void setPemPubEnd(String pemPubEnd) {
        this.pemPubEnd = pemPubEnd;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    private RSAUtils() {
    }

    private RSAUtils(String priKeyPath, String pubKeyPath) throws Exception {
        this.privateKey = getPrivateKey(priKeyPath);
        this.publicKey = getPublicKey(pubKeyPath);

    }

    private RSAUtils(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        this.privateKey = privateKey;
        this.publicKey = publicKey;

    }

    public static RSAUtils getInstance() throws Exception {
        if (null == instance) {
            synchronized (RSAUtils.class) {
                if(null == instance) {
                    instance = new RSAUtils();
                }
            }
        }
        return instance;
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

    public static RSAUtils getInstance(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        if (null == instance) {
            synchronized (RSAUtils.class) {
                if(null == instance) {
                    instance = new RSAUtils(privateKey, publicKey);
                }
            }
        } else {
            instance.privateKey = privateKey;
            instance.publicKey = publicKey;
        }
        return instance;
    }


    /**
     * @Description: 公钥加密
     * @Param: oriData 待加密数据
     * @return: byte[] 加密数据
     */
    public byte[] encrypt(String oriData) throws Exception {
        byte[] data = oriData.getBytes();
        // 对数据加密
        Cipher cipher = Cipher.getInstance(encryptAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(data);
        return encrypted;
    }


    /**
     * @Description: 私钥解密
     * @Param: enData 待解密数据
     * @return: Stirng 解密数据
     */
    public String decrypt(byte[] enData) throws Exception {
        Cipher cipher = Cipher.getInstance(encryptAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] original = cipher.doFinal(enData);
        String originalString = new String(original);
        return originalString;
    }

    /**
     * @Description: 签名
     * 签名的作用
     * @Param: oriData 待签名数据
     * @return: byte[] 数字签名
     */
    public byte[] sign(String oriData) throws Exception {
        byte[] data = oriData.getBytes();
        // 实例化Signature
        Signature signature = Signature.getInstance(signatureAlgorithm);
        // 初始化Signature
        signature.initSign(privateKey);
        // 更新
        signature.update(data);
        // 签名
        byte[] encrypted= signature.sign();

        return encrypted;
    }


    /**
     * @Description: 验签
     * @Param: sign 签名
     * @return: boolean 是否通过验签
     */
    public boolean verify(byte[] sign, String oriData) throws Exception {
        byte[] data = oriData.getBytes();
        // 实例化Signature
        Signature signature = Signature.getInstance(signatureAlgorithm);
        // 初始化Signature
        signature.initVerify(publicKey);
        // 更新
        signature.update(data);

        return signature.verify(sign);
    }

    /**
     * @Description: 取得私钥
     * @Param: keyFile 私钥文件路径(pem格式)
     *         部分PEM文件的头尾不是"-----BEGIN PRIVATE KEY-----\n"
     * @return: PrivateKey 私钥
     */
    public PrivateKey getPrivateKey(String keyFile) throws Exception {
        File f = new File(keyFile);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes);
        String privKeyPEM = temp.replace(pemPriHead, "");
        privKeyPEM = privKeyPEM.replace(pemPriEnd, "");

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
    public PublicKey getPublicKey(String keyFile) throws Exception {
        File f = new File(keyFile);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes);
        String publicKeyPEM = temp.replace(pemPubHead, "");
        publicKeyPEM = publicKeyPEM.replace(pemPubEnd, "");

        byte[] decoded = new BASE64Decoder().decodeBuffer(publicKeyPEM);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm);
        return kf.generatePublic(spec);
    }

}
