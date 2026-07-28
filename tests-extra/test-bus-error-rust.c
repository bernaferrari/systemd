/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: Rust sd_bus_error accessor functions */

#include "tests.h"
#include "sd-bus.h"
#include "bus-error.h"

/* Rust FFI */
#include "rust/bus_error_util.h"

/* ── bus_error_is_dirty ─────────────────────────────────────────────────── */
/* RUST-CONTRACT: bus-error-is-dirty */

TEST(bus_error_is_dirty_null) {
        assert_se(rs_bus_error_is_dirty(NULL) == bus_error_is_dirty(NULL));
}

TEST(bus_error_is_dirty_clean) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(rs_bus_error_is_dirty(&e) == bus_error_is_dirty(&e));
}

TEST(bus_error_is_dirty_name_set) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.AccessDenied", "Access denied");
        assert_se(rs_bus_error_is_dirty(&e) == bus_error_is_dirty(&e));
}

TEST(bus_error_is_dirty_message_set) {
        sd_bus_error e = { .name = NULL, .message = "Some error", ._need_free = 0 };
        assert_se(rs_bus_error_is_dirty(&e) == bus_error_is_dirty(&e));
}

TEST(bus_error_is_dirty_need_free) {
        sd_bus_error e = { .name = NULL, .message = NULL, ._need_free = 1 };
        assert_se(rs_bus_error_is_dirty(&e) == bus_error_is_dirty(&e));
}

TEST(bus_error_is_dirty_need_free_negative) {
        sd_bus_error e = { .name = NULL, .message = NULL, ._need_free = -1 };
        assert_se(rs_bus_error_is_dirty(&e) == bus_error_is_dirty(&e));
}

/* ── sd_bus_error_is_set ────────────────────────────────────────────────── */
/* RUST-CONTRACT: sd-bus-error-is-set */

TEST(sd_bus_error_is_set_null) {
        assert_se(rs_sd_bus_error_is_set(NULL) == sd_bus_error_is_set(NULL));
}

TEST(sd_bus_error_is_set_unset) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(rs_sd_bus_error_is_set(&e) == sd_bus_error_is_set(&e));
}

TEST(sd_bus_error_is_set_set) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        assert_se(rs_sd_bus_error_is_set(&e) == sd_bus_error_is_set(&e));
}

TEST(sd_bus_error_is_set_name_only) {
        sd_bus_error e = { .name = "some.error.Name", .message = NULL, ._need_free = 0 };
        assert_se(rs_sd_bus_error_is_set(&e) == sd_bus_error_is_set(&e));
}

/* ── sd_bus_error_has_name ──────────────────────────────────────────────── */
/* RUST-CONTRACT: sd-bus-error-has-name */

TEST(sd_bus_error_has_name_null) {
        assert_se(rs_sd_bus_error_has_name(NULL, "some.error") == sd_bus_error_has_name(NULL, "some.error"));
}

TEST(sd_bus_error_has_name_unset) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(rs_sd_bus_error_has_name(&e, "some.error") == sd_bus_error_has_name(&e, "some.error"));
}

TEST(sd_bus_error_has_name_matching) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        assert_se(rs_sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.Failed") == sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.Failed"));
}

TEST(sd_bus_error_has_name_not_matching) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        assert_se(rs_sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.AccessDenied") == sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.AccessDenied"));
}

TEST(sd_bus_error_has_name_both_null) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(rs_sd_bus_error_has_name(&e, NULL) == sd_bus_error_has_name(&e, NULL)); /* both NULL → match */
}

TEST(sd_bus_error_has_name_one_null) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        assert_se(rs_sd_bus_error_has_name(&e, NULL) == sd_bus_error_has_name(&e, NULL)); /* one NULL, one not → no match */
}

TEST(sd_bus_error_has_name_prefix_match) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        /* "org.freedesktop.DBus.Error.Fail" is a prefix but not equal */
        assert_se(rs_sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.Fail") == sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.Fail"));
}

DEFINE_TEST_MAIN(LOG_INFO);
