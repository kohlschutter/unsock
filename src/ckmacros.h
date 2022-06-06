/*
 * unsock: shim to automatically change AF_INET sockets to AF_UNIX, etc.
 *
 * Copyright 2022 Christian Kohlschuetter <christian@kohlschutter.com>
 * SPDX-License-Identifier: Apache-2.0
 * See NOTICE and LICENSE for license details.
*/
#ifndef ckmacros_h
#define ckmacros_h

#if __GNUC__
#   define CK_IGNORE_CAST_BEGIN \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wint-to-pointer-cast\"") \
_Pragma("GCC diagnostic ignored \"-Wpointer-to-int-cast\"") \
_Pragma("GCC diagnostic ignored \"-Wbad-function-cast\"") \
_Pragma("GCC diagnostic ignored \"-Wcast-function-type\"")
#   define CK_IGNORE_CAST_END \
_Pragma("GCC diagnostic pop")
#else
#   define CK_IGNORE_CAST_BEGIN
#   define CK_IGNORE_CAST_END
#endif

#if defined(_WIN32)
#  define CK_VISIBILITY_INTERNAL
#  define CK_VISIBILITY_DEFAULT
#elif __clang
#  define CK_VISIBILITY_INTERNAL __attribute__((visibility("internal")))
#  define CK_VISIBILITY_DEFAULT __attribute__((visibility("default")))
#else
#  define CK_VISIBILITY_INTERNAL __attribute__((visibility("hidden")))
#  define CK_VISIBILITY_DEFAULT __attribute__((visibility("default")))
#endif

#endif /* ckmacros_h */
