//
//  AESCBC.m
//
//  Created by bastiandev on 19.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>

#import "AESCBC.h"

@implementation AESCBC

+ (NSData *) perform: (UInt32)operation :(NSData *)inputBytes :(NSData *)keyBytes :(NSData *)ivBytes {
    size_t numBytes = 0;
    NSMutableData * resultBytes = [[NSMutableData alloc] initWithLength:[inputBytes length] + kCCBlockSizeAES128];
    CCCryptorStatus cryptStatus = CCCrypt(
                                          operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyBytes.bytes, kCCKeySizeAES256,
                                          ivBytes.length ? ivBytes.bytes : nil,
                                          inputBytes.bytes, inputBytes.length,
                                          resultBytes.mutableBytes, resultBytes.length,
                                          &numBytes);

    if (cryptStatus == kCCSuccess) {
        [resultBytes setLength:numBytes];
        return resultBytes;
    }
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}

+ (NSData *) encrypt: (NSData *)inputBytes :(NSData *)keyBytes :(NSData *)ivBytes {
    return [self perform:kCCEncrypt :inputBytes :keyBytes :ivBytes];
}
+ (NSData *) decrypt: (NSData *)cipherBytes :(NSData *)keyBytes :(NSData *)ivBytes {
    return [self perform:kCCDecrypt :cipherBytes :keyBytes :ivBytes];
}

@end
