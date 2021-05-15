package com.tectiv3.aes;

import java.io.UnsupportedEncodingException;

import java.util.UUID;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import com.ownfin.aes.crypto.AESCBC;
import com.ownfin.aes.crypto.CSPRNG;
import com.ownfin.aes.encoding.Base64;

public class RCTAes extends ReactContextBaseJavaModule {

    public static final String HMAC_SHA_256 = "HmacSHA256";
    public static final String HMAC_SHA_512 = "HmacSHA512";

    public RCTAes(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RCTAes";
    }

    @ReactMethod
    public void encrypt(String inputBase, String keyBase, String ivBase, Promise promise) {
        try {
            byte[] inputBytes = Base64.toBytes(inputBase);
            byte[] keyBytes = Base64.toBytes(keyBase);
            byte[] ivBytes = null;
            if(ivBase != null && ivBase.length() > 0){
                ivBytes = Base64.toBytes(ivBase);
            }
            byte[] resultBytes = AESCBC.encrypt(inputBytes, keyBytes, ivBytes);
            String resultBase = Base64.toString(resultBytes);
            promise.resolve(resultBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void decrypt(String cipherBase, String keyBase, String ivBase, Promise promise) {
        try {
            byte[] cipherBytes = Base64.toBytes(cipherBase);
            byte[] keyBytes = Base64.toBytes(keyBase);
            byte[] ivBytes = Base64.toBytes(ivBase);
            byte[] plainBytes = AESCBC.encrypt(cipherBytes, keyBytes, ivBytes);
            String plainBase = Base64.toString(plainBytes);
            promise.resolve(plainBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void pbkdf2(String pwd, String salt, Integer cost, Integer length, Promise promise) {
        try {
            String strs = pbkdf2(pwd, salt, cost, length);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void hmac256(String data, String pwd, Promise promise) {
        try {
            String strs = hmacX(data, pwd, HMAC_SHA_256);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void hmac512(String data, String pwd, Promise promise) {
        try {
            String strs = hmacX(data, pwd, HMAC_SHA_512);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha1(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-1");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void sha256(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-256");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void sha512(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-512");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomUuid(Promise promise) {
        try {
            String result = UUID.randomUUID().toString();
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void randomKey(Integer byteCount, Promise promise) {
        try {
            byte[] randomBytes = CSPRNG.generate(byteCount);
            String randomBase = Base64.toString(randomBytes);
            promise.resolve(randomBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    private String shaX(String data, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] dataBytes = Base64.toBytes(data);
        md.update(dataBytes);
        byte[] digest = md.digest();
        return Base64.toString(digest);
    }

    private static String pbkdf2(String input, String salt, Integer cost, Integer length)
    throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException
    {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        byte[] inputBytes = Base64.toBytes(input);
        byte[] saltBytes = Base64.toBytes(salt);
        gen.init(inputBytes, saltBytes, cost);
        byte[] keyBytes = ((KeyParameter) gen.generateDerivedParameters(length)).getKey();
        return Base64.toString(keyBytes);
    }

    private static String hmacX(String text, String key, String algorithm)
    throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException
    {
        byte[] contentBytes = Base64.toBytes(text);
        byte[] keyBytes = Base64.toBytes(key);
        Mac sha_HMAC = Mac.getInstance(algorithm);
        SecretKey secret_key = new SecretKeySpec(keyBytes, algorithm);
        sha_HMAC.init(secret_key);
        byte[] macBytes = sha_HMAC.doFinal(contentBytes);
        return Base64.toString(macBytes);
    }

}
