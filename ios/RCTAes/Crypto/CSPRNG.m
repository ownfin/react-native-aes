//
//  CSPRNG.m
//
//  Created by bastiandev on 19.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import "CSPRNG.h"

@implementation CSPRNG

+ (NSData *) generate: (NSInteger)byteCount {
    NSMutableData *randomBytes = [NSMutableData dataWithLength:byteCount];
    int resultCode = SecRandomCopyBytes(kSecRandomDefault, byteCount, randomBytes.mutableBytes);
    if (resultCode != noErr) {
        return nil;
    }
    return randomBytes;
}

@end
