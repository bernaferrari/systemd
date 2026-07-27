/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "machine-credential.h"
#include "string-util.h"
#include "tests.h"

TEST(machine_credential_context_done_empty) {
        MachineCredentialContext ctx = {};
        machine_credential_context_done(&ctx);
        assert_se(ctx.credentials == NULL);
        assert_se(ctx.n_credentials == 0);
}

TEST(machine_credential_find_empty) {
        MachineCredentialContext ctx = {};
        assert_se(machine_credential_find(&ctx, "test") == NULL);
}

TEST(machine_credential_add_and_find) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext ctx = {};
        int r;

        r = machine_credential_add(&ctx, "test-id", "test-value", strlen("test-value"));
        assert_se(r >= 0);
        assert_se(ctx.n_credentials == 1);

        MachineCredential *c = machine_credential_find(&ctx, "test-id");
        assert_se(c != NULL);
        assert_se(streq(c->id, "test-id"));
        assert_se(streq(c->data, "test-value"));
        assert_se(c->size == strlen("test-value"));

        /* Non-existent credential */
        assert_se(machine_credential_find(&ctx, "nonexistent") == NULL);
}

TEST(machine_credential_add_multiple) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext ctx = {};
        int r;

        r = machine_credential_add(&ctx, "cred1", "value1", strlen("value1"));
        assert_se(r >= 0);

        r = machine_credential_add(&ctx, "cred2", "value2", strlen("value2"));
        assert_se(r >= 0);

        r = machine_credential_add(&ctx, "cred3", "value3", strlen("value3"));
        assert_se(r >= 0);

        assert_se(ctx.n_credentials == 3);
        assert_se(machine_credential_find(&ctx, "cred1") != NULL);
        assert_se(machine_credential_find(&ctx, "cred2") != NULL);
        assert_se(machine_credential_find(&ctx, "cred3") != NULL);
        assert_se(machine_credential_find(&ctx, "cred4") == NULL);
}

TEST(machine_credential_set_basic) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext ctx = {};
        int r;

        r = machine_credential_set(&ctx, "mycred:myvalue");
        assert_se(r >= 0);
        assert_se(ctx.n_credentials == 1);

        MachineCredential *c = machine_credential_find(&ctx, "mycred");
        assert_se(c != NULL);
        assert_se(streq(c->id, "mycred"));
        assert_se(streq(c->data, "myvalue"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
