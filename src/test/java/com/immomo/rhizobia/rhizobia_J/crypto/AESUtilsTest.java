package com.immomo.rhizobia.rhizobia_J.crypto;

import org.junit.Test;
import org.junit.Assert;

public class AESUtilsTest {

    private final byte[] foo = {26, 58, -78, 28, 39, -106, -66, -2,
            -23, 12, 1, 78, -35, 17, -124, 26};
    private final byte[] bar = {-106, -17, -12, -49, 0, 2, 55, 111,
            -79, -63, -115, 100, -63, 99, -52, 121};

    @Test
    public void testEncrypt() throws Exception {
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
}
