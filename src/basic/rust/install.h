/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Keep the parameter type owned by the current C authority. This declaration
 * is intentionally not a second `InstallChange` mirror. */
#include "install.h"

/* `changes` may be NULL only with n_changes == 0. Otherwise it must identify
 * n_changes readable InstallChange objects. The Rust facade reads only type. */
bool rs_install_changes_have_modification(const InstallChange *changes, size_t n_changes);
bool rs_INSTALL_CHANGE_TYPE_VALID(int type);
