/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Shadow test for device property validation function ported from
 * src/libsystemd/sd-device/device-util.c to src/basic/rust/device_property.rs
 *
 * Note: The C original lives in libsystemd which is not linked here,
 * so we use expected-value assertions instead of C-vs-Rust comparison. */

#include <assert.h>
#include <string.h>

#include "tests.h"

#include "rust/device_property.h"

static void test_readonly_properties_rejected(void) {
        /* Kernel netlink-only properties */
        assert_se(!rs_device_property_can_set("ACTION"));
        assert_se(!rs_device_property_can_set("SEQNUM"));
        assert_se(!rs_device_property_can_set("SYNTH_UUID"));

        /* Kernel netlink + uevent properties */
        assert_se(!rs_device_property_can_set("DEVPATH"));
        assert_se(!rs_device_property_can_set("DEVPATH_OLD"));
        assert_se(!rs_device_property_can_set("SUBSYSTEM"));
        assert_se(!rs_device_property_can_set("DEVTYPE"));
        assert_se(!rs_device_property_can_set("DRIVER"));
        assert_se(!rs_device_property_can_set("MODALIAS"));

        /* Device node properties */
        assert_se(!rs_device_property_can_set("DEVNAME"));
        assert_se(!rs_device_property_can_set("DEVMODE"));
        assert_se(!rs_device_property_can_set("DEVUID"));
        assert_se(!rs_device_property_can_set("DEVGID"));
        assert_se(!rs_device_property_can_set("MAJOR"));
        assert_se(!rs_device_property_can_set("MINOR"));

        /* Block device */
        assert_se(!rs_device_property_can_set("DISKSEQ"));
        assert_se(!rs_device_property_can_set("PARTN"));

        /* Network interface */
        assert_se(!rs_device_property_can_set("IFINDEX"));
        assert_se(!rs_device_property_can_set("INTERFACE"));
        assert_se(!rs_device_property_can_set("INTERFACE_OLD"));

        /* udevd-set properties */
        assert_se(!rs_device_property_can_set("DEVLINKS"));
        assert_se(!rs_device_property_can_set("TAGS"));
        assert_se(!rs_device_property_can_set("CURRENT_TAGS"));
        assert_se(!rs_device_property_can_set("USEC_INITIALIZED"));
        assert_se(!rs_device_property_can_set("UDEV_DATABASE_VERSION"));
}

static void test_synth_arg_prefix_rejected(void) {
        assert_se(!rs_device_property_can_set("SYNTH_ARG_FOO"));
        assert_se(!rs_device_property_can_set("SYNTH_ARG_BAR"));
        assert_se(!rs_device_property_can_set("SYNTH_ARG_"));
}

static void test_writable_properties_accepted(void) {
        assert_se(rs_device_property_can_set("ID_MODEL"));
        assert_se(rs_device_property_can_set("ID_SERIAL"));
        assert_se(rs_device_property_can_set("ID_PATH"));
        assert_se(rs_device_property_can_set("SYSTEMD_WANTS"));
        assert_se(rs_device_property_can_set("TAG"));
        assert_se(rs_device_property_can_set("CUSTOM_PROP"));
        /* Close but not exact match */
        assert_se(rs_device_property_can_set("SYNTH_UUIDX"));
        /* Prefix without underscore */
        assert_se(rs_device_property_can_set("SYNTH_ARG"));
}

static void test_null_rejected(void) {
        assert_se(!rs_device_property_can_set(NULL));
}

int main(int argc, char *argv[]) {
        test_readonly_properties_rejected();
        test_synth_arg_prefix_rejected();
        test_writable_properties_accepted();
        test_null_rejected();

        return 0;
}
