/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * Compatibility include for shared callers. Keep the ABI declarations in
 * src/basic/rust/fstype_util.h so this forwarding header cannot drift from
 * the Rust implementation's canonical interface.
 */
#include "../../basic/rust/fstype_util.h"
