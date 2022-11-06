//
//  HMAC.h
//
//  Created by bastiandev on 20.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface HMAC : NSObject
+ (NSData *) hash256: (NSData *)inputBytes :(NSData *)keyBytes;
+ (NSData *) hash512: (NSData *)inputBytes :(NSData *)keyBytes;
@end
