package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.crypto.ECDSAUtils;
import org.junit.Test;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.junit.Assert.*;

public class ECDSAUtilsTest {

    @Test
    public void sign() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(160);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

        ECDSAUtils ecInstance = ECDSAUtils.getInstance(ecPrivateKey, ecPublicKey);

//        String priKeyPath = "/tmp/pri.key";
//        String pubKeyPath = "/tmp/pub.key";
//        ECDSAUtils ecInstance = ECDSAUtils.getInstance(priKeyPath, pubKeyPath);


        String plaintext = "123";

        byte[] sigintext = ecInstance.sign(plaintext);
        System.out.println(sigintext.toString());
        String signtRet = new BASE64Encoder().encode(sigintext);
        System.out.println("sign : " + signtRet);

        //验签
        byte[] verified = new BASE64Decoder().decodeBuffer(signtRet);
        boolean ifPass = ecInstance.verify(verified, plaintext);
        System.out.println("pass or not : " + ifPass);
        assertTrue(ifPass);

        plaintext = "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";

        sigintext = ecInstance.sign(plaintext);
        System.out.println(sigintext.toString());
        signtRet = new BASE64Encoder().encode(sigintext);
        System.out.println("sign : " + signtRet);

        //验签
        verified = new BASE64Decoder().decodeBuffer(signtRet);
        ifPass = ecInstance.verify(verified, plaintext);
        System.out.println("pass or not : " + ifPass);
        assertTrue(ifPass);

    }
}