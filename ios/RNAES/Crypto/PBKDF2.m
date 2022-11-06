//
//  PBKDF2.m
//
//  Created by bastiandev on 20.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonCryptoError.h>

#import "PBKDF2.h"

@implementation PBKDF2

+ (NSData *) derive:(NSData *)inputBytes :(NSData *)saltBytes :(NSInteger)iterations :(NSInteger)byteCount {
    NSMutableData *keyBytes = [[NSMutableData alloc] initWithLength:byteCount];
    int status = CCKeyDerivationPBKDF(kCCPBKDF2,
                                      inputBytes.bytes, inputBytes.length,
                                      saltBytes.bytes, saltBytes.length,
                                      kCCPRFHmacAlgSHA512,
                                      (int)iterations,
                                      keyBytes.mutableBytes, keyBytes.length);
    if (status == kCCParamError) {
        NSLog(@"Key derivation error");
        return nil;
    }
    return keyBytes;
}

@end
