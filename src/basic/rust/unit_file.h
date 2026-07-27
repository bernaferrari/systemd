/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

/* Raw integer parameters deliberately preserve invalid C UnitType inputs. */
bool rs_unit_type_may_alias(int type);
bool rs_unit_type_may_template(int type);
