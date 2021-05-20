//
//  RNAES.m
//
//  Created by tectiv3 on 10/02/17.
//  Copyright (c) 2017 tectiv3. All rights reserved.
//  Refactored by bastiandev on 20.05.21.
//  Copyright (c) 2021 ownfin. All rights reserved.
//


#import "RNAES.h"

#import "AESCBC.h"
#import "Base64.h"
#import "CSPRNG.h"
#import "HMAC.h"
#import "PBKDF2.h"
#import "SHA.h"

@implementation RNAES

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(aesEncrypt:(NSString *)inputBase :(NSString *)ivBase :(NSString *)keyBase
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *inputBytes = [Base64 toBytes:inputBase];
    NSData *keyBytes = [Base64 toBytes:keyBase];
    NSData *ivBytes = [Base64 toBytes:ivBase];
    NSData *resultBytes = [AESCBC encrypt:inputBytes :keyBytes :ivBytes];
    if (resultBytes == nil) {
        reject(@"encrypt_fail", @"Encrypt error", error);
    } else {
        NSString *resultBase = [Base64 toString:resultBytes];
        resolve(resultBase);
    }
}

RCT_EXPORT_METHOD(aesDecrypt:(NSString *)cipherBase :(NSString *)ivBase :(NSString *)keyBase
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *cipherBytes = [Base64 toBytes:cipherBase];
    NSData *keyBytes = [Base64 toBytes:keyBase];
    NSData *ivBytes = [Base64 toBytes:ivBase];
    NSData *plainBytes = [AESCBC decrypt:cipherBytes :keyBytes :ivBytes];
    if (plainBytes == nil) {
        reject(@"decrypt_fail", @"Decrypt failed", error);
    } else {
        NSString *plainBase = [Base64 toString:plainBytes];
        resolve(plainBase);
    }
}

RCT_EXPORT_METHOD(pbkdf2:(NSString *)inputBase :(NSString *)saltBase :(NSInteger)iterations :(NSInteger)byteCount
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *inputBytes = [Base64 toBytes:inputBase];
    NSData *saltBytes = [Base64 toBytes:saltBase];
    NSData *keyBytes = [PBKDF2 derive:inputBytes :saltBytes :iterations :byteCount];
    if (keyBytes == nil) {
        reject(@"keygen_fail", @"Key generation failed", error);
    } else {
        NSString *keyBase = [Base64 toString:keyBytes];
        resolve(keyBase);
    }
}

RCT_EXPORT_METHOD(hmac256:(NSString *)inputBase :(NSString *)keyBase
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *inputBytes = [Base64 toBytes:inputBase];
    NSData *keyBytes = [Base64 toBytes:keyBase];
    NSData *macBytes = [HMAC hash256:inputBytes :keyBytes];
    if (macBytes == nil) {
        reject(@"hmac_fail", @"HMAC error", error);
    } else {
        NSString *macBase = [Base64 toString:macBytes];
        resolve(macBase);
    }
}

RCT_EXPORT_METHOD(hmac512:(NSString *)inputBase :(NSString *)keyBase
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *inputBytes = [Base64 toBytes:inputBase];
    NSData *keyBytes = [Base64 toBytes:keyBase];
    NSData *macBytes = [HMAC hash512:inputBytes :keyBytes];
    if (macBytes == nil) {
        reject(@"hmac_fail", @"HMAC error", error);
    } else {
        NSString *macBase = [Base64 toString:macBytes];
        resolve(macBase);
    }
}

RCT_EXPORT_METHOD(sha1:(NSString *)inputBase
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *inputBytes = [Base64 toBytes:inputBase];
    NSData *hashBytes = [SHA hash1:inputBytes];
    if (hashBytes == nil) {
        reject(@"sha1_fail", @"Hash error", error);
    } else {
        NSString *hashBase = [Base64 toString:hashBytes];
        resolve(hashBase);
    }
}

RCT_EXPORT_METHOD(sha256:(NSString *)inputBase
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *inputBytes = [Base64 toBytes:inputBase];
    NSData *hashBytes = [SHA hash256:inputBytes];
    if (hashBytes == nil) {
        reject(@"sha1_fail", @"Hash error", error);
    } else {
        NSString *hashBase = [Base64 toString:hashBytes];
        resolve(hashBase);
    }
}

RCT_EXPORT_METHOD(sha512:(NSString *)inputBase
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *inputBytes = [Base64 toBytes:inputBase];
    NSData *hashBytes = [SHA hash512:inputBytes];
    if (hashBytes == nil) {
        reject(@"sha1_fail", @"Hash error", error);
    } else {
        NSString *hashBase = [Base64 toString:hashBytes];
        resolve(hashBase);
    }
}

RCT_EXPORT_METHOD(csprng:(NSInteger)byteCount
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *randomBytes = [CSPRNG generate:byteCount];
    if (randomBytes == nil) {
        reject(@"random_fail", @"Random key error", error);
    } else {
        NSString *randomBase = [Base64 toString:randomBytes];
        resolve(randomBase);
    }
}

RCT_EXPORT_METHOD(uuid:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *uuidString = [[NSUUID UUID] UUIDString];
    if (uuidString == nil) {
        reject(@"uuid_fail", @"Uuid error", error);
    } else {
        resolve(uuidString);
    }
}

@end
