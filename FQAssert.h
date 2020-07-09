//
// Copyright (c) 2008-present, Meitu, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the LICENSE file in
// the root directory of this source tree.
//
// Created on: 2020/5/20
// Created by: fuqi
//


#import <Foundation/Foundation.h>


#define HXAssert(condition,desc,...) \
do {\
__PRAGMA_PUSH_NO_EXTRA_ARG_WARNINGS \
NSString *backtrace = [FQAssert backtrace];\
NSString *info = [NSString stringWithFormat:@"%@\n\n\n%@",desc,backtrace];\
if (__builtin_expect(!(condition),0)) {\
UIAlertView * av = [[UIAlertView alloc] initWithTitle:@"断言崩溃，将在5秒后退出，请及时截图" message:info delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil];\
[av show];\
dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(50 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{\
NSString *__assert_file__ = [NSString stringWithUTF8String:__FILE__];\
__assert_file__ = __assert_file__ ?__assert_file__: @"<Unknow file>";\
[[NSAssertionHandler currentHandler] handleFailureInMethod:_cmd object:self file:__assert_file__ lineNumber:__LINE__ description:(desc),##__VA_ARGS__];\
});\
}\
__PRAGMA_POP_NO_EXTRA_ARG_WARNINGS\
} while(0)


@interface FQAssert : NSObject
+ (NSString *)backtrace;
@end

