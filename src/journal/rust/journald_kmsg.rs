// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-kmsg.c
//
// journald /dev/kmsg reading and kernel message processing.

crate::journal_port_module!(
    "journald /dev/kmsg reading and kernel message processing.",
    "src/journal/journald-kmsg.c",
    [
        "manager_forward_kmsg",
        "dev_kmsg_record",
        "manager_flush_dev_kmsg",
        "manager_open_dev_kmsg",
        "manager_open_kernel_seqnum",
        "manager_close_kernel_seqnum",
        "manager_reopen_dev_kmsg",
    ]
);
