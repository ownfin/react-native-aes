package com.ownfin.aes.crypto;

import com.ownfin.aes.encoding.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCBC {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    private static final String KEY_ALGORITHM = "AES";
    private final static IvParameterSpec emptyIvSpec = new IvParameterSpec(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

    public static String encrypt(String inputBase, String keyBase, String ivBase) throws Exception {
        if (inputBase == null || inputBase.length() == 0) {
            return null;
        }

        byte[] inputBytes = Base64.toBytes(inputBase);
        byte[] keyBytes = Base64.toBytes(keyBase);
        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        IvParameterSpec ivSpec = emptyIvSpec;
        if(ivBase != null){
            byte[] ivBytes = Base64.toBytes(ivBase);
            ivSpec = new IvParameterSpec(ivBytes);
        }
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] cipherBytes = cipher.doFinal(inputBytes);
        return Base64.toString(cipherBytes);
    }
    public static String decrypt(String cipherBase, String keyBase, String ivBase) throws Exception {
        if(cipherBase == null || cipherBase.length() == 0) {
            return null;
        }

        byte[] cipherBytes = Base64.toBytes(cipherBase);
        byte[] keyBytes = Base64.toBytes(keyBase);
        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        IvParameterSpec ivSpec = emptyIvSpec;
        if(ivBase != null){
            byte[] ivBytes = Base64.toBytes(ivBase);
            ivSpec = new IvParameterSpec(ivBytes);
        }
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return Base64.toString(plainBytes);
    }

}
