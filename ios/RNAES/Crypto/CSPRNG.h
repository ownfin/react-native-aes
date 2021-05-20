//
//  CSPRNG.h
//
//  Created by bastiandev on 19.05.21.
//  Copyright © 2021 ownfin. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CSPRNG : NSObject
+ (NSData *) generate: (NSInteger)byteCount;
@end
