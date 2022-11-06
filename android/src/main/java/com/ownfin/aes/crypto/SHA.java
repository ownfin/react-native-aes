package com.ownfin.aes.crypto;

import java.security.MessageDigest;

public class SHA {

    public static SHA SHA1 = new SHA("SHA-1");
    public static SHA SHA256 = new SHA("SHA-256");
    public static SHA SHA512 = new SHA("SHA-512");

    private String algorithm;

    public SHA(String algorithm){
        this.algorithm = algorithm;
    }

    public byte[] hash(byte[] inputBytes) throws Exception
    {
        MessageDigest md = MessageDigest.getInstance(this.algorithm);
        md.update(inputBytes);
        byte[] hashBytes = md.digest();
        return hashBytes;
    }

}
