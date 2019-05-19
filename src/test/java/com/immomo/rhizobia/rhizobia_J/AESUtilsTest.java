package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.crypto.AESUtils;
import org.junit.Test;
import sun.misc.BASE64Encoder;

import static org.junit.Assert.*;

public class AESUtilsTest {
    AESUtils aesInstance = AESUtils.getInstance("843739488","Yc%*#nM!5gyX3Gpq3q#YfzpCx5^cXY@E",null);

    @Test
    public void encrypt() {
        try {
            String orginText = "10000";
            byte[] ciphertext = aesInstance.encrypt(orginText);
            String encryptRet = new BASE64Encoder().encode(ciphertext);
            System.out.println(aesInstance.getaesKey());
            System.out.println("加密后的字串是：" + encryptRet);
            String deRet = aesInstance.decrypt(ciphertext);
            System.out.println(deRet);
            assertTrue(orginText.equals(deRet));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void decrypt() {
    }
}