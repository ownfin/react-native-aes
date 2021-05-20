//
//  SHA.m
//
//  Created by bastiandev on 20.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>

#import "SHA.h"

@implementation SHA

+ (NSData *) hash1: (NSData *)inputBytes {
    NSMutableData *hashBytes = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([inputBytes bytes], (CC_LONG)[inputBytes length], hashBytes.mutableBytes);
    return hashBytes;
}

+ (NSData *) hash256: (NSData *)inputBytes {
    NSMutableData *hashBytes = [[NSMutableData alloc] initWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([inputBytes bytes], (CC_LONG)[inputBytes length], hashBytes.mutableBytes);
    return hashBytes;
}

+ (NSData *) hash512: (NSData *)inputBytes {
    NSMutableData *hashBytes = [[NSMutableData alloc] initWithLength:CC_SHA512_DIGEST_LENGTH];
    CC_SHA512([inputBytes bytes], (CC_LONG)[inputBytes length], hashBytes.mutableBytes);
    return hashBytes;
}

@end
