/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: src/shared/compare-operator.c,src/shared/web-util.c,src/shared/color-util.c,src/shared/boot-entry.c,src/shared/pkcs11-util.c,src/shared/user-record.c */
#pragma once

#include <stdbool.h>
#include <stdint.h>

bool rs_http_etag_is_valid(const char *etag);
bool rs_http_url_is_valid(const char *url);
bool rs_file_url_is_valid(const char *url);
bool rs_documentation_url_is_valid(const char *url);
void rs_rgb_to_hsv(double r, double g, double b, double *ret_h, double *ret_s, double *ret_v);
void rs_hsv_to_rgb(double h, double s, double v, uint8_t *ret_r, uint8_t *ret_g, uint8_t *ret_b);
int rs_parse_compare_operator(const char **s, int flags);
int rs_test_order(int k, int op);
bool rs_boot_entry_token_valid(const char *p);
bool rs_pkcs11_uri_valid(const char *uri);
int rs_suitable_blob_filename(const char *name);
