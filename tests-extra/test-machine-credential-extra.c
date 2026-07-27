/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "machine-credential.h"
#include "string-util.h"
#include "tests.h"

TEST(machine_credential_find_empty) {
        MachineCredentialContext ctx = {};

        /* Empty context → NULL */
        assert_se(machine_credential_find(&ctx, "test") == NULL);
}

TEST(machine_credential_add_and_find) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext ctx = {};
        int r;

        /* Add a credential */
        r = machine_credential_add(&ctx, "mycred", "myvalue", strlen("myvalue"));
        assert_se(r >= 0);
        assert_se(ctx.n_credentials == 1);

        /* Find it */
        MachineCredential *cred = machine_credential_find(&ctx, "mycred");
        assert_se(cred != NULL);
        assert_se(streq(cred->id, "mycred"));
        assert_se(streq(cred->data, "myvalue"));

        /* Find nonexistent */
        assert_se(machine_credential_find(&ctx, "other") == NULL);
}

TEST(machine_credential_add_duplicate) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext ctx = {};

        /* Add first */
        assert_se(machine_credential_add(&ctx, "dup", "val1", 4) >= 0);

        /* Duplicate → -EEXIST */
        assert_se(machine_credential_add(&ctx, "dup", "val2", 4) == -EEXIST);
}

TEST(machine_credential_add_invalid_name) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext ctx = {};

        /* Empty name → -EINVAL */
        assert_se(machine_credential_add(&ctx, "", "val", 3) == -EINVAL);
        /* Name with slash → -EINVAL */
        assert_se(machine_credential_add(&ctx, "invalid/name", "val", 3) == -EINVAL);
        /* Name with dot-dot → -EINVAL */
        assert_se(machine_credential_add(&ctx, "..", "val", 3) == -EINVAL);
}

TEST(machine_credential_add_multiple) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext ctx = {};

        assert_se(machine_credential_add(&ctx, "cred1", "val1", 4) >= 0);
        assert_se(machine_credential_add(&ctx, "cred2", "val2", 4) >= 0);
        assert_se(machine_credential_add(&ctx, "cred3", "val3", 4) >= 0);
        assert_se(ctx.n_credentials == 3);

        assert_se(machine_credential_find(&ctx, "cred2") != NULL);
        assert_se(machine_credential_find(&ctx, "cred1") != NULL);
        assert_se(machine_credential_find(&ctx, "cred3") != NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
