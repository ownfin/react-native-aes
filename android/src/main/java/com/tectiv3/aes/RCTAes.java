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
import com.ownfin.aes.crypto.HMAC;
import com.ownfin.aes.crypto.PBKDF2;
import com.ownfin.aes.crypto.SHA;
import com.ownfin.aes.encoding.Base64;

public class RCTAes extends ReactContextBaseJavaModule {

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
            byte[] plainBytes = AESCBC.decrypt(cipherBytes, keyBytes, ivBytes);
            String plainBase = Base64.toString(plainBytes);
            promise.resolve(plainBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void pbkdf2(String inputBase, String saltBase, Integer iterations, Integer byteCount, Promise promise) {
        try {
            byte[] inputBytes = Base64.toBytes(inputBase);
            byte[] saltBytes = Base64.toBytes(saltBase);
            byte[] keyBytes = PBKDF2.derive(inputBytes, saltBytes, iterations, byteCount);
            String keyBase = Base64.toString(keyBytes);
            promise.resolve(keyBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void hmac256(String inputBase, String keyBase, Promise promise) {
        try {
            byte[] inputBytes = Base64.toBytes(inputBase);
            byte[] keyBytes = Base64.toBytes(keyBase);
            byte[] macBytes = HMAC.HMAC256.hash(inputBytes, keyBytes);
            String macBase = Base64.toString(macBytes);
            promise.resolve(macBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void hmac512(String inputBase, String keyBase, Promise promise) {
        try {
            byte[] inputBytes = Base64.toBytes(inputBase);
            byte[] keyBytes = Base64.toBytes(keyBase);
            byte[] macBytes = HMAC.HMAC512.hash(inputBytes, keyBytes);
            String macBase = Base64.toString(macBytes);
            promise.resolve(macBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha1(String inputBase, Promise promise) {
        try {
            byte[] inputBytes = Base64.toBytes(inputBase);
            byte[] hashBytes = SHA.SHA1.hash(inputBytes);
            String hashBase = Base64.toString(hashBytes);
            promise.resolve(hashBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void sha256(String inputBase, Promise promise) {
        try {
            byte[] inputBytes = Base64.toBytes(inputBase);
            byte[] hashBytes = SHA.SHA256.hash(inputBytes);
            String hashBase = Base64.toString(hashBytes);
            promise.resolve(hashBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void sha512(String inputBase, Promise promise) {
        try {
            byte[] inputBytes = Base64.toBytes(inputBase);
            byte[] hashBytes = SHA.SHA512.hash(inputBytes);
            String hashBase = Base64.toString(hashBytes);
            promise.resolve(hashBase);
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

}
