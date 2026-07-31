/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * C/R link and fail-closed smoke harness for volatile-root.
 *
 * The Rust entry point performs only mount-ID/mountinfo preflight on /proc
 * and returns before discovery, symlink creation, or mount operations. This
 * must stay safe to execute directly on a test host: it does not unshare or
 * alter the caller's mount namespace.
 */

#include <signal.h>

extern int rs_volatile_root_refuse_proc_transition(void);
int rs_get_sigrtmin(void);
int rs_get_sigrtmax(void);
int rs_get_nsig(void);

/*
 * The Rust static archive contains the shared basic signal helpers. Their
 * host ABI values are intentionally supplied exactly as the existing C/R
 * basic shadow tests do, even though this preflight path does not call them.
 */
int rs_get_sigrtmin(void) {
        return SIGRTMIN;
}

int rs_get_sigrtmax(void) {
        return SIGRTMAX;
}

int rs_get_nsig(void) {
        return _NSIG;
}

int main(void) {
        return rs_volatile_root_refuse_proc_transition() == 0 ? 0 : 1;
}
