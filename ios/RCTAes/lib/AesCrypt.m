//
//  AesCrypt.m
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>

#import "AesCrypt.h"

@implementation AesCrypt

+ (NSString *) bytesToBase:(NSData *)inputData {
    NSString *base64Encoded = [inputData base64EncodedStringWithOptions:0];
    return base64Encoded;
}
+ (NSData *) baseToBytes: (NSString *)inputBase {
    NSData *base64Decoded = [[NSData alloc] initWithBase64EncodedString:inputBase options:0];;
    return base64Decoded;
}

+ (NSString *) pbkdf2:(NSString *)input salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length {
    // Data of String to generate Hash key(hexa decimal string).
    NSData *inputData = [self baseToBytes:input];
    NSData *saltData = [self baseToBytes:salt];

    // Hash key (hexa decimal) string data length.
    NSMutableData *hashKeyData = [NSMutableData dataWithLength:length/8];

    // Key Derivation using PBKDF2 algorithm.
    int status = CCKeyDerivationPBKDF(
                    kCCPBKDF2,
                    inputData.bytes,
                    inputData.length,
                    saltData.bytes,
                    saltData.length,
                    kCCPRFHmacAlgSHA512,
                    (int)cost,
                    hashKeyData.mutableBytes,
                    hashKeyData.length);

    if (status == kCCParamError) {
        NSLog(@"Key derivation error");
        return @"";
    }

    return [self bytesToBase:hashKeyData];
}

+ (NSData *) AES256CBC: (NSString *)operation inputBase: (NSString *)inputBase keyBase: (NSString *)keyBase iv: (NSString *)iv {
    //convert base64 string to hex data
    NSData *inputData = [self baseToBytes:inputBase];
    NSData *keyData = [self baseToBytes:keyBase];
    NSData *ivData = [self baseToBytes:iv];
    
    size_t numBytes = 0;
    NSMutableData * buffer = [[NSMutableData alloc] initWithLength:[inputData length] + kCCBlockSizeAES128];

    CCCryptorStatus cryptStatus = CCCrypt(
                                          [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes, kCCKeySizeAES256,
                                          ivData.length ? ivData.bytes : nil,
                                          inputData.bytes, inputData.length,
                                          buffer.mutableBytes,  buffer.length,
                                          &numBytes);

    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}

+ (NSString *) encrypt: (NSString *)inputBase key: (NSString *)keyBase iv: (NSString *)iv {
    NSData *result = [self AES256CBC:@"encrypt" inputBase:inputBase keyBase:keyBase iv:iv];
    return [self bytesToBase:result];
}
+ (NSString *) decrypt: (NSString *)inputBase key: (NSString *)keyBase iv: (NSString *)iv {
    NSData *result = [self AES256CBC:@"decrypt" inputBase:inputBase keyBase:keyBase iv:iv];
    return [self bytesToBase:result];
}

+ (NSString *) hmac256: (NSString *)inputBase key: (NSString *)keyBase {
    NSData *inputData = [self baseToBytes:inputBase];
    NSData *keyData = [self baseToBytes:keyBase];
    
    void* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA256, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self bytesToBase:nsdata];
}
+ (NSString *) hmac512: (NSString *)inputBase key: (NSString *)keyBase {
    NSData *inputData = [self baseToBytes:inputBase];
    NSData *keyData = [self baseToBytes:keyBase];
    
    void* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA512, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self bytesToBase:nsdata];
}

+ (NSString *) sha1: (NSString *)inputBase {
    NSData* inputData = [self baseToBytes:inputBase];
    NSMutableData *result = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([inputData bytes], (CC_LONG)[inputData length], result.mutableBytes);
    return [self bytesToBase:result];
}

+ (NSString *) sha256: (NSString *)inputBase {
    NSData* inputData = [self baseToBytes:inputBase];
    unsigned char* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self bytesToBase:result];
}

+ (NSString *) sha512: (NSString *)inputBase {
    NSData* inputData = [self baseToBytes:inputBase];
    unsigned char* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CC_SHA512([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self bytesToBase:result];
}

+ (NSString *) randomUuid {
  return [[NSUUID UUID] UUIDString];
}

+ (NSString *) randomKey: (NSInteger)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    if (result != noErr) {
        return nil;
    }
    return [self bytesToBase:data];
}

@end
