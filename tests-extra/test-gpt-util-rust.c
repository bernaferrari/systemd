/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C GPT partition verity helpers and parse_vlanid vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"

/* C headers */
#include "gpt.h"
#include "string-util.h"
#include "vlan-util.h"

/* Rust FFI */
#include "rust/gpt_util.h"

/* ── partition_designator_is_versioned ───────────────────────────────── */

static void test_partition_designator_is_versioned(void) {
        bool cv, rv;

        /* Versioned partitions */
        cv = partition_designator_is_versioned(PARTITION_ROOT);
        rv = rs_partition_designator_is_versioned(PARTITION_ROOT);
        assert_se(cv == rv);
        assert_se(cv);

        cv = partition_designator_is_versioned(PARTITION_USR);
        rv = rs_partition_designator_is_versioned(PARTITION_USR);
        assert_se(cv == rv);
        assert_se(cv);

        cv = partition_designator_is_versioned(PARTITION_ROOT_VERITY);
        rv = rs_partition_designator_is_versioned(PARTITION_ROOT_VERITY);
        assert_se(cv == rv);
        assert_se(cv);

        cv = partition_designator_is_versioned(PARTITION_USR_VERITY);
        rv = rs_partition_designator_is_versioned(PARTITION_USR_VERITY);
        assert_se(cv == rv);
        assert_se(cv);

        cv = partition_designator_is_versioned(PARTITION_ROOT_VERITY_SIG);
        rv = rs_partition_designator_is_versioned(PARTITION_ROOT_VERITY_SIG);
        assert_se(cv == rv);
        assert_se(cv);

        cv = partition_designator_is_versioned(PARTITION_USR_VERITY_SIG);
        rv = rs_partition_designator_is_versioned(PARTITION_USR_VERITY_SIG);
        assert_se(cv == rv);
        assert_se(cv);

        /* Non-versioned partitions */
        cv = partition_designator_is_versioned(PARTITION_HOME);
        rv = rs_partition_designator_is_versioned(PARTITION_HOME);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = partition_designator_is_versioned(PARTITION_SWAP);
        rv = rs_partition_designator_is_versioned(PARTITION_SWAP);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = partition_designator_is_versioned(PARTITION_ESP);
        rv = rs_partition_designator_is_versioned(PARTITION_ESP);
        assert_se(cv == rv);
        assert_se(!cv);
}

/* ── partition verity hash/sig helpers ────────────────────────────────── */

static void test_partition_verity_helpers(void) {
        PartitionDesignator cv, rv;

        /* verity_hash_of */
        cv = partition_verity_hash_of(PARTITION_ROOT);
        rv = rs_partition_verity_hash_of(PARTITION_ROOT);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_ROOT_VERITY);

        cv = partition_verity_hash_of(PARTITION_USR);
        rv = rs_partition_verity_hash_of(PARTITION_USR);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_USR_VERITY);

        cv = partition_verity_hash_of(PARTITION_HOME);
        rv = rs_partition_verity_hash_of(PARTITION_HOME);
        assert_se(cv == rv);
        assert_se(cv == _PARTITION_DESIGNATOR_INVALID);

        /* verity_sig_of */
        cv = partition_verity_sig_of(PARTITION_ROOT);
        rv = rs_partition_verity_sig_of(PARTITION_ROOT);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_ROOT_VERITY_SIG);

        cv = partition_verity_sig_of(PARTITION_USR);
        rv = rs_partition_verity_sig_of(PARTITION_USR);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_USR_VERITY_SIG);

        cv = partition_verity_sig_of(PARTITION_SWAP);
        rv = rs_partition_verity_sig_of(PARTITION_SWAP);
        assert_se(cv == rv);
        assert_se(cv == _PARTITION_DESIGNATOR_INVALID);

        /* verity_hash_to_data */
        cv = partition_verity_hash_to_data(PARTITION_ROOT_VERITY);
        rv = rs_partition_verity_hash_to_data(PARTITION_ROOT_VERITY);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_ROOT);

        cv = partition_verity_hash_to_data(PARTITION_USR_VERITY);
        rv = rs_partition_verity_hash_to_data(PARTITION_USR_VERITY);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_USR);

        cv = partition_verity_hash_to_data(PARTITION_ROOT);
        rv = rs_partition_verity_hash_to_data(PARTITION_ROOT);
        assert_se(cv == rv);
        assert_se(cv == _PARTITION_DESIGNATOR_INVALID);

        /* verity_sig_to_data */
        cv = partition_verity_sig_to_data(PARTITION_ROOT_VERITY_SIG);
        rv = rs_partition_verity_sig_to_data(PARTITION_ROOT_VERITY_SIG);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_ROOT);

        cv = partition_verity_sig_to_data(PARTITION_USR_VERITY_SIG);
        rv = rs_partition_verity_sig_to_data(PARTITION_USR_VERITY_SIG);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_USR);

        cv = partition_verity_sig_to_data(PARTITION_SWAP);
        rv = rs_partition_verity_sig_to_data(PARTITION_SWAP);
        assert_se(cv == rv);
        assert_se(cv == _PARTITION_DESIGNATOR_INVALID);

        /* verity_to_data (combined) */
        cv = partition_verity_to_data(PARTITION_ROOT_VERITY);
        rv = rs_partition_verity_to_data(PARTITION_ROOT_VERITY);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_ROOT);

        cv = partition_verity_to_data(PARTITION_ROOT_VERITY_SIG);
        rv = rs_partition_verity_to_data(PARTITION_ROOT_VERITY_SIG);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_ROOT);

        cv = partition_verity_to_data(PARTITION_USR_VERITY);
        rv = rs_partition_verity_to_data(PARTITION_USR_VERITY);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_USR);

        cv = partition_verity_to_data(PARTITION_USR_VERITY_SIG);
        rv = rs_partition_verity_to_data(PARTITION_USR_VERITY_SIG);
        assert_se(cv == rv);
        assert_se(cv == PARTITION_USR);

        cv = partition_verity_to_data(PARTITION_HOME);
        rv = rs_partition_verity_to_data(PARTITION_HOME);
        assert_se(cv == rv);
        assert_se(cv == _PARTITION_DESIGNATOR_INVALID);
}

/* ── partition_mountpoint ────────────────────────────────────────────── */

static void test_partition_mountpoint(void) {
        const char *cv, *rv;

        cv = partition_mountpoint_to_string(PARTITION_ROOT);
        rv = rs_partition_mountpoint_to_string(PARTITION_ROOT);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "/"));

        cv = partition_mountpoint_to_string(PARTITION_USR);
        rv = rs_partition_mountpoint_to_string(PARTITION_USR);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "/usr"));

        cv = partition_mountpoint_to_string(PARTITION_ESP);
        rv = rs_partition_mountpoint_to_string(PARTITION_ESP);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "/efi"));

        cv = partition_mountpoint_to_string(PARTITION_SWAP);
        rv = rs_partition_mountpoint_to_string(PARTITION_SWAP);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        cv = partition_mountpoint_to_string(PARTITION_ROOT_VERITY);
        rv = rs_partition_mountpoint_to_string(PARTITION_ROOT_VERITY);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        cv = partition_mountpoint_to_string(PARTITION_TMP);
        rv = rs_partition_mountpoint_to_string(PARTITION_TMP);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "/var/tmp"));

        cv = partition_mountpoint_to_string(PARTITION_VAR);
        rv = rs_partition_mountpoint_to_string(PARTITION_VAR);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "/var"));

        /* Out of range */
        cv = partition_mountpoint_to_string(-1);
        rv = rs_partition_mountpoint_to_string(-1);
        assert_se(cv == NULL);
        assert_se(rv == NULL);
}

/* ── parse_vlanid ────────────────────────────────────────────────────── */

static void test_parse_vlanid(void) {
        uint16_t cv, rv;
        int cr, rr;

        /* Valid VLAN IDs */
        cr = parse_vlanid("0", &cv);
        rr = rs_parse_vlanid("0", &rv);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cv == rv);
        assert_se(cv == 0);

        cr = parse_vlanid("100", &cv);
        rr = rs_parse_vlanid("100", &rv);
        assert_se(cr == rr);
        assert_se(cv == 100);

        cr = parse_vlanid("4094", &cv);
        rr = rs_parse_vlanid("4094", &rv);
        assert_se(cr == rr);
        assert_se(cv == 4094);

        /* Invalid: too large */
        cr = parse_vlanid("4095", &cv);
        rr = rs_parse_vlanid("4095", &rv);
        assert_se(cr == rr);
        assert_se(cr == -ERANGE);

        /* Invalid: not a number */
        cr = parse_vlanid("abc", &cv);
        rr = rs_parse_vlanid("abc", &rv);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* Invalid: empty */
        cr = parse_vlanid("", &cv);
        rr = rs_parse_vlanid("", &rv);
        assert_se(cr == rr);
        assert_se(cr == -EINVAL);

        /* Valid with leading whitespace */
        cr = parse_vlanid("  42", &cv);
        rr = rs_parse_vlanid("  42", &rv);
        assert_se(cr == rr);
        assert_se(cv == 42);
}

/* ── gpt_partition_label_valid ────────────────────────────────────────── */

static void test_gpt_partition_label_valid(void) {
        int cv, rv;

        /* Short ASCII label */
        cv = gpt_partition_label_valid("root");
        rv = rs_gpt_partition_label_valid("root");
        assert_se(cv == rv);
        assert_se(cv > 0); /* true: 4 <= 36 */

        /* Empty label */
        cv = gpt_partition_label_valid("");
        rv = rs_gpt_partition_label_valid("");
        assert_se(cv == rv);
        assert_se(cv > 0); /* true: 0 <= 36 */

        /* 36 ASCII chars should be OK */
        cv = gpt_partition_label_valid("abcdefghijklmnopqrstuvwxyz0123456789");
        rv = rs_gpt_partition_label_valid("abcdefghijklmnopqrstuvwxyz0123456789");
        assert_se(cv == rv);
        assert_se(cv > 0); /* true: 36 <= 36 */

        /* 37 ASCII chars should fail (GPT_LABEL_MAX=36) */
        cv = gpt_partition_label_valid("abcdefghijklmnopqrstuvwxyz0123456789x");
        rv = rs_gpt_partition_label_valid("abcdefghijklmnopqrstuvwxyz0123456789x");
        assert_se(cv == rv);
        assert_se(cv == 0); /* false: 37 > 36 */

        /* Multi-byte UTF-8 chars — each becomes one UTF-16 code unit */
        /* 18 two-byte UTF-8 chars = 18 UTF-16 code units, within limit */
        cv = gpt_partition_label_valid("äöüéèêàâîôûäöüéèêàâî");
        rv = rs_gpt_partition_label_valid("äöüéèêàâî");
        assert_se(cv == rv);
        assert_se(cv > 0); /* true */
}

int main(int argc, char **argv) {
        test_partition_designator_is_versioned();
        test_partition_verity_helpers();
        test_partition_mountpoint();
        test_parse_vlanid();
        test_gpt_partition_label_valid();
        return 0;
}
