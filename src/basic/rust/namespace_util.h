/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int rs_clone_flag_to_namespace_type(unsigned long clone_flag);
bool rs_userns_shift_range_valid(unsigned int shift, unsigned int range);
