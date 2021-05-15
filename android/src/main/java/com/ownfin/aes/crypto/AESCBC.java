package com.ownfin.aes.crypto;

import com.ownfin.aes.encoding.Base64;
import com.ownfin.aes.util.ByteArrayCombiner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCBC {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final Integer IV_BYTE_COUNT = 16;
    private final static IvParameterSpec emptyIvSpec = new IvParameterSpec(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

    public static String encrypt(String inputBase, String keyBase, String ivBase) throws Exception {
        byte[] inputBytes = Base64.toBytes(inputBase);
        byte[] keyBytes = Base64.toBytes(keyBase);
        byte[] ivBytes = null;
        if(ivBase != null && ivBase.length() > 0){
            ivBytes = Base64.toBytes(ivBase);
        }
        else{
            ivBytes = CSPRNG.generate(IV_BYTE_COUNT);
        }

        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] cipherBytes = cipher.doFinal(inputBytes);
        byte[] outputBytes = ByteArrayCombiner.combine(ivBytes, cipherBytes);
        return Base64.toString(outputBytes);
    }
    public static String decrypt(String cipherBase, String keyBase, String ivBase) throws Exception {
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
