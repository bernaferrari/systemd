/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fs-util.h"
#include "lock-util.h"
#include "string-util.h"
#include "tests.h"

TEST(make_lock_file_for_basic) {
        _cleanup_free_ char *t = NULL;
        assert_se(asprintf(&t, "/tmp/test-lock-util-extra2-%lu.lock", (unsigned long) getpid()) >= 0);

        LockFile lock = LOCK_FILE_INIT;
        int r = make_lock_file_for(t, LOCK_BSD, &lock);
        log_debug("make_lock_file_for: %d", r);
        release_lock_file(&lock);
        (void) unlink(t);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
