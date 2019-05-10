package com.immomo.rhizobia.rhizobia_J.extra.commons;
/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Reference implementation of the Randomizer interface. This implementation builds on the JCE provider to provide a
 * cryptographically strong source of entropy.
 */
public class RandomCreater {
    /**
     *
     */
    public SecureRandom secureRandom = null;

    public RandomCreater() throws NoSuchProviderException, NoSuchAlgorithmException {
        secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
    }

    public String getRandomString(int length, char[] characterSet) {
        StringBuilder sb = new StringBuilder();
        for (int loop = 0; loop < length; loop++) {
            int index = secureRandom.nextInt(characterSet.length);
            sb.append(characterSet[index]);
        }
        String nonce = sb.toString();
        return nonce;
    }

    /**
     *
     */
    public boolean getRandomBoolean() {
        return secureRandom.nextBoolean();
    }

    /**
     * {@inheritDoc}
     */
    public int getRandomInteger(int min, int max) {
        return secureRandom.nextInt(max - min) + min;
    }

    /**
     * {@inheritDoc}
     */
    public long getRandomLong() {
        return secureRandom.nextLong();
    }

    /**
     * {@inheritDoc}
     */
    public float getRandomReal(float min, float max) {
        float factor = max - min;
        return secureRandom.nextFloat() * factor + min;
    }

    /**
     * {@inheritDoc}
     */
    public String getRandomFilename(String extension) {
        String fn = getRandomString(12, EncoderConstants.CHAR_ALPHANUMERICS) + "." + extension;
        return fn;
    }

    /**
     * {@inheritDoc}
     */
    public String getRandomGUID() {
        return UUID.randomUUID().toString();
    }

    /**
     * {@inheritDoc}
     */
    public byte[] getRandomBytes(int n) {
        byte[] result = new byte[n];
        secureRandom.nextBytes(result);
        return result;
    }

    /**
     * @param decript 要加密的字符串
     * @return 加密的字符串
     * SHA1加密
     */
    public final String sha256(String decript) {
        try {
            MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            digest.update(decript.getBytes());
            byte messageDigest[] = digest.digest();
            // Create Hex String
            StringBuffer hexString = new StringBuffer();
            // 字节数组转换为 十六进制 数
            for (int i = 0; i < messageDigest.length; i++) {
                String shaHex = Integer.toHexString(messageDigest[i] & 0xFF);
                if (shaHex.length() < 2) {
                    hexString.append(0);
                }
                hexString.append(shaHex);
            }
            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * @param decript 要加密的字符串
     * @return 加密的字符串
     * MD5加密
     */
    public final String md5(String decript) {
        char hexDigits[] = { // 用来将字节转换成 16 进制表示的字符
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        try {
            byte[] strTemp = decript.getBytes();
            MessageDigest mdTemp = MessageDigest.getInstance("MD5");
            mdTemp.update(strTemp);
            byte tmp[] = mdTemp.digest(); // MD5 的计算结果是一个 128 位的长整数，
            // 用字节表示就是 16 个字节
            char strs[] = new char[16 * 2]; // 每个字节用 16 进制表示的话，使用两个字符，
            // 所以表示成 16 进制需要 32 个字符
            int k = 0; // 表示转换结果中对应的字符位置
            for (int i = 0; i < 16; i++) { // 从第一个字节开始，对 MD5 的每一个字节
                // 转换成 16 进制字符的转换
                byte byte0 = tmp[i]; // 取第 i 个字节
                strs[k++] = hexDigits[byte0 >>> 4 & 0xf]; // 取字节中高 4 位的数字转换,
                // >>> 为逻辑右移，将符号位一起右移
                strs[k++] = hexDigits[byte0 & 0xf]; // 取字节中低 4 位的数字转换
            }
            return new String(strs).toUpperCase(); // 换后的结果转换为字符串
        } catch (Exception e) {
            return null;
        }
    }

}


