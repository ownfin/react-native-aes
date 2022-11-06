//
//  AESCBC.h
//
//  Created by bastiandev on 19.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <Foundation/Foundation.h>

#define IV_BYTE_COUNT 16

@interface AESCBC : NSObject
+ (NSData *) encrypt: (NSData *)inputBytes :(NSData *)ivBytes :(NSData *)keyBytes;
+ (NSData *) decrypt: (NSData *)cipherBytes :(NSData *)ivBytes :(NSData *)keyBytes;
@end
