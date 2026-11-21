// SPDX-License-Identifier: GPL-2.0-only
/*
 * susfs_priority_hook.h - getpriority/setpriority interception for the susfs
 * 2.4 priority UID filter (CMD_SUSFS_SET_PRIORITY_UID_FILTER, 0x60030).
 *
 * The filter's setter and bitmap live in susfs_uid_filter.c; this file is the
 * hook that consumes them.  Installed from the uid_filter layer, non-fatally:
 * if the table entries cannot be patched the module still loads and the
 * filter simply stays inert (the setter keeps succeeding, as before).
 */

#ifndef __SUSFS_PRIORITY_HOOK_H
#define __SUSFS_PRIORITY_HOOK_H

int susfs_priority_hook_init(void);
void susfs_priority_hook_exit(void);

#endif /* __SUSFS_PRIORITY_HOOK_H */
