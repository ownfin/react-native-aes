//
//  Base64.h
//
//  Created by bastiandev on 19.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Base64 : NSObject
+ (NSString *) toString: (NSData *)inputBytes;
+ (NSData *) toBytes: (NSString *)inputBase;
@end
