//
//  SHA.h
//
//  Created by bastiandev on 20.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SHA : NSObject
+ (NSData *) hash1: (NSData *)inputBytes;
+ (NSData *) hash256: (NSData *)inputBytes;
+ (NSData *) hash512: (NSData *)inputBytes;
@end
