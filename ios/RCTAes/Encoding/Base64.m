//
//  Base64.m
//
//  Created by bastiandev on 19.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import "Base64.h"

@implementation Base64
+ (NSString *) toString:(NSData *)inputBytes {
    return [inputBytes base64EncodedStringWithOptions:0];
}
+ (NSData *) toBytes: (NSString *)inputBase {
    if(inputBase != nil){
        return [[NSData alloc] initWithBase64EncodedString:inputBase options:0];
    }
    return nil;
}
@end
