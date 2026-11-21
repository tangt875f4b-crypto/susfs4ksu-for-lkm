// SPDX-License-Identifier: GPL-2.0-only
/*
 * susfs_priority_hook.c - hide filtered UIDs from getpriority/setpriority.
 *
 * Upstream susfs 2.4 (kernel/sys.c, CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER)
 * filters only the PRIO_USER branch: when the caller is an app
 * (uid >= 10000) asking about another user's priority (who != 0, target !=
 * caller) and the target UID is in the priority bitmap, the syscall returns
 * -ESRCH, as if the UID had no processes.  PRIO_PROCESS and PRIO_PGRP are
 * untouched upstream, and so are they here.
 *
 * An LKM cannot patch kernel/sys.c, so the two syscalls are intercepted with
 * the sys_call_table patcher (susfs_fp_hook), the same mechanism the
 * supercall, openat and create-gate layers already use.  Native and 32-bit
 * entries are patched separately: the tables do NOT share a numbering
 * (native getpriority is 141, compat getpriority is 96; native setpriority
 * is 140, compat setpriority is 97), so both numbers are written out
 * explicitly - never one number for both tables.
 *
 * The wrappers call the saved original from their orig_slot, never the table
 * (which points back at the wrapper after install).  Install failure is
 * non-fatal: the layer logs it and the filter stays inert.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/cred.h>		/* current_uid() */
#include <linux/user_namespace.h>	/* current_user_ns() */
#include <linux/uidgid.h>		/* make_kuid(), uid_eq(), uid_valid() */
#include <linux/resource.h>		/* PRIO_USER */
#include <asm/unistd.h>		/* __NR_getpriority, __NR_setpriority */
#include <asm/ptrace.h>		/* struct pt_regs: the wrappers read the caller's arguments */
#include "susfs_fp_hook.h"
#include "susfs.h"		/* susfs_is_priority_uid_filtered() */
#include "susfs_log.h"
#include "susfs_priority_hook.h"

/* AArch32 numbers from arch/arm/tools/syscall.tbl: 96 getpriority,
 * 97 setpriority.  Written out, never derived from the native __NR_*
 * values - native 141 is getpriority but compat 141 is getdents. */
#define SUSFS_COMPAT_NR_GETPRIORITY	96
#define SUSFS_COMPAT_NR_SETPRIORITY	97

static susfs_syscall_fn_t priority_orig_getpriority;
static susfs_syscall_fn_t priority_orig_compat_getpriority;
static susfs_syscall_fn_t priority_orig_setpriority;
static susfs_syscall_fn_t priority_orig_compat_setpriority;

/* Shared gate, mirroring upstream kernel/sys.c: true when this call must
 * answer -ESRCH instead of reaching the real syscall.  The setpriority
 * nice value (regs->regs[2]) is ignored by the filter, exactly as upstream
 * ignores it. */
static bool susfs_priority_call_filtered(const struct pt_regs *regs)
{
	int which = (int)regs->regs[0];
	int who = (int)regs->regs[1];
	kuid_t target;

	if (which != PRIO_USER || who == 0)
		return false;
	/* who == 0 means "self" and never reaches here; a target that is the
	 * caller is exempt upstream too. */
	target = make_kuid(current_user_ns(), who);
	if (!uid_valid(target) || uid_eq(target, current_uid()))
		return false;
	/* Root and system callers always see the real priority. */
	if (current_uid().val < 10000)
		return false;
	return susfs_is_priority_uid_filtered(target.val);
}

static long __nocfi susfs_priority_getpriority(const struct pt_regs *regs)
{
	if (susfs_priority_call_filtered(regs))
		return -ESRCH;
	if (priority_orig_getpriority)
		return priority_orig_getpriority(regs);
	return -EINVAL;
}

static long __nocfi susfs_priority_compat_getpriority(const struct pt_regs *regs)
{
	if (susfs_priority_call_filtered(regs))
		return -ESRCH;
	if (priority_orig_compat_getpriority)
		return priority_orig_compat_getpriority(regs);
	return -EINVAL;
}

static long __nocfi susfs_priority_setpriority(const struct pt_regs *regs)
{
	if (susfs_priority_call_filtered(regs))
		return -ESRCH;
	if (priority_orig_setpriority)
		return priority_orig_setpriority(regs);
	return -EINVAL;
}

static long __nocfi susfs_priority_compat_setpriority(const struct pt_regs *regs)
{
	if (susfs_priority_call_filtered(regs))
		return -ESRCH;
	if (priority_orig_compat_setpriority)
		return priority_orig_compat_setpriority(regs);
	return -EINVAL;
}

static struct susfs_fp_hook priority_hooks[] = {
	{
		.nr		= __NR_getpriority,
		.nr_compat	= SUSFS_COMPAT_NR_GETPRIORITY,
		.name		= "priority/getpriority",
		.sym		= "__arm64_sys_getpriority",
		.wrapper	= susfs_priority_getpriority,
		.wrapper_compat = susfs_priority_compat_getpriority,
		.orig_slot	= &priority_orig_getpriority,
		.orig_slot_compat = &priority_orig_compat_getpriority,
	},
	{
		.nr		= __NR_setpriority,
		.nr_compat	= SUSFS_COMPAT_NR_SETPRIORITY,
		.name		= "priority/setpriority",
		.sym		= "__arm64_sys_setpriority",
		.wrapper	= susfs_priority_setpriority,
		.wrapper_compat = susfs_priority_compat_setpriority,
		.orig_slot	= &priority_orig_setpriority,
		.orig_slot_compat = &priority_orig_compat_setpriority,
	},
};

int susfs_priority_hook_init(void)
{
	int installed = 0;
	int i, rc;

	for (i = 0; i < (int)ARRAY_SIZE(priority_hooks); i++) {
		struct susfs_fp_hook *h = &priority_hooks[i];

		rc = susfs_fp_install(h);
		if (rc) {
			pr_warn("susfs priority: %s not installed (%d) - that syscall answers the kernel's own way\n",
				h->name, rc);
			continue;
		}
		installed++;
	}
	if (!installed) {
		pr_warn("susfs priority: neither priority entry could be installed\n");
		return -ENOENT;
	}
	if (installed < (int)ARRAY_SIZE(priority_hooks))
		pr_warn("susfs priority: %d of %u priority entries installed (the log above names the rest)\n",
			installed, (unsigned int)ARRAY_SIZE(priority_hooks));

	SUSFS_LOGI("susfs priority hook armed: %d of %u entries hide filtered UIDs from getpriority/setpriority\n",
		   installed, (unsigned int)ARRAY_SIZE(priority_hooks));
	return 0;
}

void susfs_priority_hook_exit(void)
{
	int armed = 0;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(priority_hooks); i++) {
		struct susfs_fp_hook *h = &priority_hooks[i];

		if (!h->installed)
			continue;
		susfs_fp_remove(h);
		armed++;
	}
	if (armed)
		susfs_fp_drain();
}
