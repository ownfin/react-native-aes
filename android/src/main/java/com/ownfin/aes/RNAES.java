package com.ownfin.aes;

import java.util.UUID;

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

public class RNAES extends ReactContextBaseJavaModule {

    public RNAES(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RNAES";
    }

    @ReactMethod
    public void aesEncrypt(String inputBase, String ivBase, String keyBase, Promise promise) {
        try {
            byte[] inputBytes = Base64.toBytes(inputBase);
            byte[] ivBytes = null;
            if(ivBase != null && ivBase.length() > 0){
                ivBytes = Base64.toBytes(ivBase);
            }
            byte[] keyBytes = Base64.toBytes(keyBase);
            byte[] resultBytes = AESCBC.encrypt(inputBytes, ivBytes, keyBytes);
            String resultBase = Base64.toString(resultBytes);
            promise.resolve(resultBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void aesDecrypt(String cipherBase, String ivBase, String keyBase, Promise promise) {
        try {
            byte[] cipherBytes = Base64.toBytes(cipherBase);
            byte[] ivBytes = Base64.toBytes(ivBase);
            byte[] keyBytes = Base64.toBytes(keyBase);
            byte[] plainBytes = AESCBC.decrypt(cipherBytes, ivBytes, keyBytes);
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
    public void csprng(Integer byteCount, Promise promise) {
        try {
            byte[] randomBytes = CSPRNG.generate(byteCount);
            String randomBase = Base64.toString(randomBytes);
            promise.resolve(randomBase);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
    @ReactMethod
    public void uuid(Promise promise) {
        try {
            String uuidString = UUID.randomUUID().toString();
            promise.resolve(uuidString);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

}
