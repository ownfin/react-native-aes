package com.ownfin.aes.encoding;

public class Base64 {

    public static String toString(byte[] inputBytes) {
        return android.util.Base64.encodeToString(inputBytes, android.util.Base64.NO_WRAP);
    }
    public static byte[] toBytes(String inputBase) {
        return android.util.Base64.decode(inputBase, android.util.Base64.NO_WRAP);
    }

}
