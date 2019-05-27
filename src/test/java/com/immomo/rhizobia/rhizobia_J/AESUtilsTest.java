package com.immomo.rhizobia.rhizobia_J;

import com.immomo.rhizobia.rhizobia_J.crypto.AESUtils;
import org.junit.Test;
import sun.misc.BASE64Encoder;

import org.junit.Assert;

import static org.junit.Assert.assertTrue;

public class AESUtilsTest {
    AESUtils aesInstance = AESUtils.getInstance("843739488","Yc%*#nM!5gyX3Gpq3q#YfzpCx5^cXY@E",null);
    private final byte[] foo = {26, 58, -78, 28, 39, -106, -66, -2,
            -23, 12, 1, 78, -35, 17, -124, 26};
    private final byte[] bar = {-106, -17, -12, -49, 0, 2, 55, 111,
            -79, -63, -115, 100, -63, 99, -52, 121};

    @Test
    public void testEncrypt() throws Exception {
        System.out.println(foo.toString());
        System.out.println(bar.toString());
        Assert.assertArrayEquals(foo,
                AESUtils.getInstance("aesKey1", "secretKey1", null)
                        .encrypt("foo"));

        Assert.assertArrayEquals(bar,
                AESUtils.getInstance("aesKey2", "secretKey2", null)
                        .encrypt("bar"));
    }

    @Test
    public void testDecrypt() throws Exception {
        Assert.assertEquals("foo",
                AESUtils.getInstance("aesKey1", "secretKey1", null)
                        .decrypt(foo));

        Assert.assertEquals("bar",
                AESUtils.getInstance("aesKey2", "secretKey2", null)
                        .decrypt(bar));
    }
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