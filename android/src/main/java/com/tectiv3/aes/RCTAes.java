package com.tectiv3.aes;

import android.widget.Toast;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import java.util.UUID;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;

import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

import android.util.Base64;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;

public class RCTAes extends ReactContextBaseJavaModule {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    public static final String HMAC_SHA_256 = "HmacSHA256";
    public static final String HMAC_SHA_512 = "HmacSHA512";
    private static final String KEY_ALGORITHM = "AES";

    public RCTAes(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RCTAes";
    }

    @ReactMethod
    public void encrypt(String data, String key, String iv, Promise promise) {
        try {
            String result = encrypt(data, key, iv);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void decrypt(String data, String pwd, String iv, Promise promise) {
        try {
            String strs = decrypt(data, pwd, iv);
            promise.resolve(strs);
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
    public void randomKey(Integer length, Promise promise) {
        try {
            byte[] key = new byte[length];
            SecureRandom rand = new SecureRandom();
            rand.nextBytes(key);
            String keyBase = bytesToBase(key);
            promise.resolve(keyBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    private String shaX(String data, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] dataBytes = baseToBytes(data);
        md.update(dataBytes);
        byte[] digest = md.digest();
        return bytesToBase(digest);
    }

    private static String pbkdf2(String input, String salt, Integer cost, Integer length)
    throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException
    {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        byte[] inputBytes = baseToBytes(input);
        byte[] saltBytes = baseToBytes(salt);
        gen.init(inputBytes, saltBytes, cost);
        byte[] keyBytes = ((KeyParameter) gen.generateDerivedParameters(length)).getKey();
        return bytesToBase(keyBytes);
    }

    private static String hmacX(String text, String key, String algorithm)
    throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException
    {
        byte[] contentBytes = baseToBytes(text);
        byte[] keyBytes = baseToBytes(key);
        Mac sha_HMAC = Mac.getInstance(algorithm);
        SecretKey secret_key = new SecretKeySpec(keyBytes, algorithm);
        sha_HMAC.init(secret_key);
        byte[] macBytes = sha_HMAC.doFinal(contentBytes);
        return bytesToBase(macBytes);
    }

    final static IvParameterSpec emptyIvSpec = new IvParameterSpec(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    private static String encrypt(String inputBase, String keyBase, String ivBase) throws Exception {
        if (inputBase == null || inputBase.length() == 0) {
            return null;
        }

        byte[] inputBytes = baseToBytes(inputBase);
        byte[] keyBytes = baseToBytes(keyBase);
        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        IvParameterSpec ivSpec = emptyIvSpec;
        if(ivBase != null){
            byte[] ivBytes = baseToBytes(ivBase);
            ivSpec = new IvParameterSpec(ivBytes);
        }
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] cipherBytes = cipher.doFinal(inputBytes);
        return bytesToBase(cipherBytes);
    }
    private static String decrypt(String cipherBase, String keyBase, String ivBase) throws Exception {
        if(cipherBase == null || cipherBase.length() == 0) {
            return null;
        }

        byte[] cipherBytes = baseToBytes(cipherBase);
        byte[] keyBytes = baseToBytes(keyBase);
        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        IvParameterSpec ivSpec = emptyIvSpec;
        if(ivBase != null){
            byte[] ivBytes = baseToBytes(ivBase);
            ivSpec = new IvParameterSpec(ivBytes);
        }
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return bytesToBase(plainBytes);
    }


    public static String bytesToBase(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }
    public static byte[] baseToBytes(String base) {
        return Base64.decode(base, Base64.NO_WRAP);
    }

}
