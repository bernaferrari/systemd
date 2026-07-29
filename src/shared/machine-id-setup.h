/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "forward.h"

typedef enum MachineIdSetupFlags {
        MACHINE_ID_SETUP_FORCE_TRANSIENT = 1 << 0,
        MACHINE_ID_SETUP_FORCE_FIRMWARE  = 1 << 1,
} MachineIdSetupFlags;

int machine_id_commit(const char *root);
int machine_id_setup(const char *root, sd_id128_t machine_id, MachineIdSetupFlags flags, sd_id128_t *ret);

/* Reads the rooted legacy D-Bus ID with the same no-follow policy used while
 * acquiring a machine ID. Returns 0 on success or a negative errno. */
int machine_id_read_dbus(const char *root, sd_id128_t *ret);
