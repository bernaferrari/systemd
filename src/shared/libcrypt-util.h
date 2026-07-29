/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlopen-note.h"
#include "forward.h"

typedef struct LibCryptFunctions {
        char* (*crypt_gensalt_ra)(const char *prefix, unsigned long count, const char *rbytes, int nrbytes);
        const char* (*crypt_preferred_method)(void);
        char* (*crypt_ra)(const char *phrase, const char *setting, void **data, int *size);
} LibCryptFunctions;

#if HAVE_LIBCRYPT
int make_salt(char **ret);
int hash_password(const char *password, char **ret);
int test_password_one(const char *hashed_password, const char *password);
int test_password_many(char **hashed_password, const char *password);

#else

static inline int hash_password(const char *password, char **ret) {
        return -EOPNOTSUPP;
}
#endif

int dlopen_libcrypt(int log_level) _dlopen_loader_;
int libcrypt_get_functions(LibCryptFunctions *ret);

bool looks_like_hashed_password(const char *s);
