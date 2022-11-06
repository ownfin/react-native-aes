package com.ownfin.aes.crypto;

import com.ownfin.aes.encoding.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HMAC {

    public static HMAC HMAC256 = new HMAC("HmacSHA256");
    public static HMAC HMAC512 = new HMAC("HmacSHA512");

    private String algorithm;

    public HMAC(String algorithm){
        this.algorithm = algorithm;
    }

    public byte[] hash(byte[] inputBytes, byte[] keyBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException
    {
        Mac macInstance = Mac.getInstance(this.algorithm);
        SecretKey secretKey = new SecretKeySpec(keyBytes, this.algorithm);
        macInstance.init(secretKey);
        byte[] macBytes = macInstance.doFinal(inputBytes);
        return macBytes;
    }

}
