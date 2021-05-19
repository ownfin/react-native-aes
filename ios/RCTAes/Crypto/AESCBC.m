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
    if(ivBytes == nil){
        ivBytes = [CSPRNG generate:IV_BYTE_COUNT];
    }
    NSData *resultBytes = [self perform:kCCEncrypt :inputBytes :keyBytes :ivBytes];
    if(resultBytes != nil){
        NSMutableData *outputBytes = [ivBytes mutableCopy];
        [outputBytes appendData:resultBytes];
        return outputBytes;
    }
    return nil;
}
+ (NSData *) decrypt: (NSData *)cipherBytes :(NSData *)keyBytes :(NSData *)ivBytes {
    return [self perform:kCCDecrypt :cipherBytes :keyBytes :ivBytes];
}

@end
