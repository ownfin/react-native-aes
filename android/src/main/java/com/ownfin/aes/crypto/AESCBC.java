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

    public static byte[] encrypt(byte[] inputBytes, byte[] keyBytes, byte[] ivBytes) throws Exception {
        if(ivBytes == null){
            ivBytes = CSPRNG.generate(IV_BYTE_COUNT);
        }

        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] cipherBytes = cipher.doFinal(inputBytes);
        byte[] outputBytes = ByteArrayCombiner.combine(ivBytes, cipherBytes);
        return outputBytes;
    }

    public static byte[] decrypt(byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes) throws Exception {
        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return plainBytes;
    }

}
