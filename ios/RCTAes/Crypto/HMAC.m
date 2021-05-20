//
//  HMAC.m
//
//  Created by bastiandev on 20.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <CommonCrypto/CommonHMAC.h>

#import "HMAC.h"

@implementation HMAC

+ (NSData *) perform: (UInt32)algorithm :(NSInteger)byteCount :(NSData *)inputBytes :(NSData *)keyBytes {
    NSMutableData *macBytes = [[NSMutableData alloc] initWithLength:byteCount];
    CCHmac(algorithm,
           [keyBytes bytes], [keyBytes length],
           [inputBytes bytes], [inputBytes length],
           macBytes.mutableBytes);
    return macBytes;
}

+ (NSData *) hash256: (NSData *)inputBytes :(NSData *)keyBytes {
    return [self perform:kCCHmacAlgSHA256 :CC_SHA256_DIGEST_LENGTH :inputBytes :keyBytes];
}
+ (NSData *) hash512: (NSData *)inputBytes :(NSData *)keyBytes {
    return [self perform:kCCHmacAlgSHA512 :CC_SHA512_DIGEST_LENGTH :inputBytes :keyBytes];
}

@end
