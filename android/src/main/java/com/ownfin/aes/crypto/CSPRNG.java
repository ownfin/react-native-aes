package com.ownfin.aes.crypto;

import java.security.SecureRandom;

public class CSPRNG {

    public static byte[] generate(Integer byteCount){
        byte[] randomBytes = new byte[byteCount];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(randomBytes);
        return randomBytes;
    }

}
