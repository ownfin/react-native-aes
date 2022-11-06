//
//  AESCBC.m
//
//  Created by bastiandev on 19.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>

#import "AESCBC.h"
#import "CSPRNG.h"

@implementation AESCBC

+ (NSData *) perform: (UInt32)operation :(NSData *)inputBytes :(NSData *)ivBytes :(NSData *)keyBytes {
    size_t outputByteCount = 0;
    size_t bufferByteCount = [inputBytes length] + kCCBlockSizeAES128;
    NSMutableData * resultBytes = [[NSMutableData alloc] initWithLength:bufferByteCount];
    CCCryptorStatus status = CCCrypt(operation,
                                     kCCAlgorithmAES128,
                                     kCCOptionPKCS7Padding,
                                     keyBytes.bytes, kCCKeySizeAES256,
                                     ivBytes.length ? ivBytes.bytes : nil,
                                     inputBytes.bytes, inputBytes.length,
                                     resultBytes.mutableBytes, resultBytes.length,
                                     &outputByteCount);
    if (status == kCCSuccess) {
        [resultBytes setLength:outputByteCount];
        return resultBytes;
    }
    NSLog(@"AES error, %d", status);
    return nil;
}

+ (NSData *) encrypt: (NSData *)inputBytes :(NSData *)ivBytes :(NSData *)keyBytes {
    if(ivBytes == nil){
        ivBytes = [CSPRNG generate:IV_BYTE_COUNT];
    }
    NSData *resultBytes = [self perform:kCCEncrypt :inputBytes :ivBytes :keyBytes];
    if(resultBytes != nil){
        NSMutableData *outputBytes = [ivBytes mutableCopy];
        [outputBytes appendData:resultBytes];
        return outputBytes;
    }
    return nil;
}
+ (NSData *) decrypt: (NSData *)cipherBytes :(NSData *)ivBytes :(NSData *)keyBytes {
    return [self perform:kCCDecrypt :cipherBytes :ivBytes :keyBytes];
}

@end
