package com.ownfin.aes.crypto;

import com.ownfin.aes.encoding.Base64;

import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBKDF2 {

    public static byte[] derive(byte[] inputBytes, byte[] saltBytes, Integer iterations, Integer byteCount)
            throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException
    {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        gen.init(inputBytes, saltBytes, iterations);
        byte[] keyBytes = ((KeyParameter) gen.generateDerivedParameters(byteCount * 8)).getKey();
        return keyBytes;
    }

}
