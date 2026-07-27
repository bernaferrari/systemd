/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: Rust sd_bus_error accessor functions */

#include "tests.h"
#include "sd-bus-protocol.h"

/* Rust FFI */
#include "rust/bus_error_util.h"

/* Local definitions (from sd-bus.h) since test doesn't link libsystemd */
#define SD_BUS_ERROR_MAKE_CONST(name, message) ((const sd_bus_error) {(name), (message), 0})
#define SD_BUS_ERROR_NULL SD_BUS_ERROR_MAKE_CONST(NULL, NULL)

/* ── bus_error_is_dirty ─────────────────────────────────────────────────── */

TEST(bus_error_is_dirty_null) {
        assert_se(rs_bus_error_is_dirty(NULL) == false);
}

TEST(bus_error_is_dirty_clean) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(rs_bus_error_is_dirty(&e) == false);
}

TEST(bus_error_is_dirty_name_set) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.AccessDenied", "Access denied");
        assert_se(rs_bus_error_is_dirty(&e) == true);
}

TEST(bus_error_is_dirty_message_set) {
        sd_bus_error e = { .name = NULL, .message = "Some error", ._need_free = 0 };
        assert_se(rs_bus_error_is_dirty(&e) == true);
}

TEST(bus_error_is_dirty_need_free) {
        sd_bus_error e = { .name = NULL, .message = NULL, ._need_free = 1 };
        assert_se(rs_bus_error_is_dirty(&e) == true);
}

TEST(bus_error_is_dirty_need_free_negative) {
        sd_bus_error e = { .name = NULL, .message = NULL, ._need_free = -1 };
        assert_se(rs_bus_error_is_dirty(&e) == true);
}

/* ── sd_bus_error_is_set ────────────────────────────────────────────────── */

TEST(sd_bus_error_is_set_null) {
        assert_se(rs_sd_bus_error_is_set(NULL) == 0);
}

TEST(sd_bus_error_is_set_unset) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(rs_sd_bus_error_is_set(&e) == 0);
}

TEST(sd_bus_error_is_set_set) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        assert_se(rs_sd_bus_error_is_set(&e) == 1);
}

TEST(sd_bus_error_is_set_name_only) {
        sd_bus_error e = { .name = "some.error.Name", .message = NULL, ._need_free = 0 };
        assert_se(rs_sd_bus_error_is_set(&e) == 1);
}

/* ── sd_bus_error_has_name ──────────────────────────────────────────────── */

TEST(sd_bus_error_has_name_null) {
        assert_se(rs_sd_bus_error_has_name(NULL, "some.error") == 0);
}

TEST(sd_bus_error_has_name_unset) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(rs_sd_bus_error_has_name(&e, "some.error") == 0);
}

TEST(sd_bus_error_has_name_matching) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        assert_se(rs_sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.Failed") == 1);
}

TEST(sd_bus_error_has_name_not_matching) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        assert_se(rs_sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.AccessDenied") == 0);
}

TEST(sd_bus_error_has_name_both_null) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(rs_sd_bus_error_has_name(&e, NULL) == 1); /* both NULL → match */
}

TEST(sd_bus_error_has_name_one_null) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        assert_se(rs_sd_bus_error_has_name(&e, NULL) == 0); /* one NULL, one not → no match */
}

TEST(sd_bus_error_has_name_prefix_match) {
        sd_bus_error e = SD_BUS_ERROR_MAKE_CONST("org.freedesktop.DBus.Error.Failed", "Operation failed");
        /* "org.freedesktop.DBus.Error.Fail" is a prefix but not equal */
        assert_se(rs_sd_bus_error_has_name(&e, "org.freedesktop.DBus.Error.Fail") == 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
