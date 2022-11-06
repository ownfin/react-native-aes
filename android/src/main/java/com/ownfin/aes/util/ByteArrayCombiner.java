package com.ownfin.aes.util;

public class ByteArrayCombiner {

    public static byte[] combine(byte[]... byteArrays){
        int totalCount = 0;
        for (byte[] byteArray : byteArrays) {
            totalCount += byteArray.length;
        }

        byte[] output = new byte[totalCount];
        int position = 0;
        for(byte[] byteArray : byteArrays){
            for (int i = 0; i < byteArray.length; i++)
            {
                output[i + position] = byteArray[i];
            }
            position += byteArray.length;
        }
        return output;
    }

}
