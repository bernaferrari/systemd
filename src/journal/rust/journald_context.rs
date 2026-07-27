// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journald-context.c
//
// journald client context metadata cache with LRU eviction.

crate::journal_port_module!(
    "journald client context metadata cache with LRU eviction.",
    "src/journal/journald-context.c",
    [
        "client_context_maybe_refresh",
        "manager_refresh_client_contexts_on_reload",
        "client_context_flush_regular",
        "client_context_flush_all",
        "client_context_get",
        "client_context_acquire",
        "client_context_release",
        "client_context_acquire_default",
    ]
);
