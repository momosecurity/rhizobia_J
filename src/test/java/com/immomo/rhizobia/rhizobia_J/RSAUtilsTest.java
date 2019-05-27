package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.crypto.RSAUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Test;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;

import static org.junit.Assert.*;

public class RSAUtilsTest {

    @Test
    public void test() {
        try{
//            String priKeyPath = "/tmp/pri.key";
//            String pubKeyPath = "/tmp/pub.key";
//            RSAUtils rsaInstance = RSAUtils.getInstance(priKeyPath, pubKeyPath);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey rsaPublicKey = (PublicKey) keyPair.getPublic();
            PrivateKey rsaPrivateKey = (PrivateKey) keyPair.getPrivate();

            RSAUtils rsaInstance = RSAUtils.getInstance(rsaPrivateKey, rsaPublicKey);

//            RSAUtils rsaInstance = RSAUtils.getInstance();
//            rsaInstance.setPemPriHead("-----BEGIN PRIVATE KEY-----\n");
//            rsaInstance.setPemPriEnd("-----END PRIVATE KEY-----");
//            rsaInstance.setPemPubHead("-----BEGIN PUBLIC KEY-----\n");
//            rsaInstance.setPemPubEnd("-----END PUBLIC KEY-----");
//            rsaInstance.setPrivateKey(rsaInstance.getPrivateKey(priKeyPath));
//            rsaInstance.setPublicKey(rsaInstance.getPublicKey(pubKeyPath));

            String plaintext = "123";
            //加密
            byte[] ciphertext = rsaInstance.encrypt(plaintext);
            System.out.println(ciphertext.toString());
            String encryptRet = new BASE64Encoder().encode(ciphertext);
            System.out.println("mi : " + encryptRet);

            //解密
            byte[] encrypted = new BASE64Decoder().decodeBuffer(encryptRet);
            String decrypted = rsaInstance.decrypt(encrypted);
            System.out.println("ming : " + decrypted);

            assertTrue(decrypted.equals(plaintext));

            //加签

            //摘要
            plaintext = DigestUtils.sha256Hex(plaintext);

            byte[] sigintext = rsaInstance.sign(plaintext);
            System.out.println(sigintext.toString());
            String signtRet = new BASE64Encoder().encode(sigintext);
            System.out.println("sign : " + signtRet);

            //验签
            byte[] verified = new BASE64Decoder().decodeBuffer(signtRet);
            boolean ifPass = rsaInstance.verify(verified, plaintext);
            System.out.println("pass or not : " + ifPass);
            assertTrue(ifPass);

            // 实例化密钥生成器
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            keyPair = keyPairGenerator.generateKeyPair();
            // 获取RSA公钥
            rsaPublicKey = (PublicKey) keyPair.getPublic();
            // 获取RSA私钥
            rsaPrivateKey = keyPair.getPrivate();


            rsaInstance = RSAUtils.getInstance(rsaPrivateKey, rsaPublicKey);

            plaintext = "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
            byte[] data = plaintext.getBytes();
            System.out.println(data.length+ " "+plaintext.length());

            //加密
            ciphertext = rsaInstance.encryptWithouLimit(plaintext);
            System.out.println(ciphertext.toString()+ " " + ciphertext.length);
            encryptRet = new BASE64Encoder().encode(ciphertext);
            System.out.println("密文 : " + encryptRet);

            //解密
            encrypted = new BASE64Decoder().decodeBuffer(encryptRet);
            decrypted = rsaInstance.decryptWithoutLimit(encrypted);
            System.out.println("明文 : " + decrypted);
            assertTrue(decrypted.equals(plaintext));

            //加签
            sigintext = rsaInstance.sign(plaintext);
            System.out.println(sigintext.toString()+ " " + sigintext.length);
            signtRet = new BASE64Encoder().encode(sigintext);
            System.out.println("加签 : " + signtRet);

            //验签
            verified = new BASE64Decoder().decodeBuffer(signtRet);
            ifPass = rsaInstance.verify(verified, plaintext);
            System.out.println("验签 : " + ifPass);
            assertTrue(ifPass);

            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}