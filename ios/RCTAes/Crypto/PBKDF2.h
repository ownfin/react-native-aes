//
//  PBKDF2.h
//
//  Created by bastiandev on 20.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PBKDF2 : NSObject
+ (NSData *) derive: (NSData *)inputBytes :(NSData *)saltBytes :(NSInteger)iterations :(NSInteger)byteCount;
@end
