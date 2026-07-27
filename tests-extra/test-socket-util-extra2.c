/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "socket-util.h"
#include "tests.h"
#include <sys/socket.h>

TEST(socket_address_type_to_string) {
        /* socket_address_type_to_string returns capitalized names */
        const char *s;

        s = socket_address_type_to_string(SOCK_STREAM);
        ASSERT_NOT_NULL(s);

        s = socket_address_type_to_string(SOCK_DGRAM);
        ASSERT_NOT_NULL(s);

        s = socket_address_type_to_string(SOCK_RAW);
        ASSERT_NOT_NULL(s);

        /* from_string works with both cases */
        ASSERT_EQ(socket_address_type_from_string("Stream"), SOCK_STREAM);
        ASSERT_EQ(socket_address_type_from_string("Datagram"), SOCK_DGRAM);
        ASSERT_EQ(socket_address_type_from_string("Raw"), SOCK_RAW);
        ASSERT_EQ(socket_address_type_from_string("SequentialPacket"), SOCK_SEQPACKET);
        ASSERT_LT(socket_address_type_from_string("invalid"), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
