// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_uid_filter.c - susfs 2.4 UID filters (LKM port of upstream fs/susfs.c).
 *
 * Upstream 2.4 added two supercall commands that take a comma-separated list of
 * app package names, resolve each name to a UID from /data/system/packages.list,
 * and keep the UIDs in an RCU bitmap over 10000-19999:
 *   CMD_SUSFS_SET_SUS_PATH_UID_FILTER 0x55554 - the listed apps are ALLOWED to
 *       see hidden sus_paths (hiding is lifted for them); every other app UID
 *       still cannot see them.  Upstream's bitmap comment says "denied" - the
 *       code says the opposite (susfs_is_inode_sus_path hides when
 *       !susfs_is_uid_allowed_for_sus_path(uid)), and this port mirrors the
 *       code, not the comment.
 *   CMD_SUSFS_SET_PRIORITY_UID_FILTER 0x60030 - the listed UIDs are hidden from
 *       getpriority/setpriority probes.  The setter and bitmap live here; the
 *       hook that consumes susfs_is_priority_uid_filtered() is
 *       susfs_priority_hook.c, which patches both syscalls' table entries
 *       (native + compat) through susfs_fp_hook - the LKM cannot patch
 *       kernel/sys.c the way upstream does.
 *
 * LKM differences from upstream (all deliberate, all documented where they
 * bite):
 *   - No susfs_switch_to_ksu_domain(): that needs ksu_cred / setup_selinux()
 *     from the built-in KernelSU image, which an LKM does not have.  The setter
 *     runs in the supercall's task_work context, i.e. with ksud's own
 *     credentials, and reads packages.list directly.  The re-resolve worker
 *     instead runs under the credentials the setter saved from ksud - the same
 *     pattern sus_path.c uses for its pending-rule resolver (save the caller's
 *     cred at SET time, override_creds() in the worker, revert afterwards).
 *   - No kernel-side trigger: in a built-in build FinaSU's pkg_observer calls
 *     susfs_parse_*_app_strings() on packages.list changes; in an LKM build
 *     that call is compiled out.  This file therefore re-checks the mtime of
 *     /data/system/packages.list every 120s (delayed work, only while a filter
 *     is set) and re-resolves when it changed.  The parse_*() entry points are
 *     still exported for any future in-kernel caller.
 *   - No setup_selinux / ksu_cred resolution is attempted: if ksud's saved
 *     credentials cannot read packages.list, the SET returns that errno instead
 *     of silently succeeding with an empty bitmap.
 */
#include <linux/module.h>
#include <linux/version.h>	/* LINUX_VERSION_CODE / KERNEL_VERSION */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/bitmap.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/stddef.h>
#include <linux/jiffies.h>
#include "susfs_abi.h"
#include "susfs.h"
#include "susfs_log.h"
#include "susfs_priority_hook.h"

#define SUSFS_PACKAGES_LIST_PATH "/data/system/packages.list"
#define SUSFS_PACKAGES_LIST_MAX_SIZE (4 * 1024 * 1024)
#define SUSFS_UID_FILTER_RECHECK_MS (120 * 1000)

struct susfs_uid_filter_bitmap {
	struct rcu_head rcu;
	unsigned long bits[SUSFS_UID_FILTER_BITMAP_LEN];
};

struct susfs_uid_filter {
	struct susfs_uid_filter_bitmap __rcu *bitmap;
	struct mutex lock;		/* serialises writers; readers are RCU */
	char *app_strings;		/* stored names, for re-resolution */
	atomic_t running;		/* one re-resolve worker at a time */
	const struct cred *caller_cred;	/* ksud's cred, saved at SET time */
	struct mutex cred_lock;
	const char *label;
	/* mtime baseline for the delayed re-check */
	time64_t last_mtime_sec;
	long last_mtime_nsec;
	loff_t last_size;
	bool have_mtime;
};

static struct susfs_uid_filter sus_path_filter;
static struct susfs_uid_filter priority_filter;
static struct delayed_work susfs_uid_filter_recheck_work;
static bool susfs_uid_filter_inited;

static bool susfs_is_valid_app_name(const char *app_name)
{
	const char *p = app_name;
	size_t len = strlen(app_name);

	if (len == 0 || len > 255)
		return false;
	if (!strcmp(app_name, ".") || !strcmp(app_name, ".."))
		return false;
	for (; *p != '\0'; p++) {
		if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '.' || *p == '_')
			continue;
		return false;
	}
	return true;
}

static int susfs_parse_ulong(const char *s, unsigned long *out)
{
	unsigned long v = 0;
	const char *p = s;

	if (!*p)
		return -EINVAL;
	for (; *p; p++) {
		if (*p < '0' || *p > '9')
			return -EINVAL;
		if (v > (ULONG_MAX - 9) / 10)
			return -EINVAL;
		v = v * 10 + (unsigned long)(*p - '0');
	}
	*out = v;
	return 0;
}

/* Resolve one app package name to a UID from packages.list.  Runs with the
 * caller's credentials (setter) or with the saved caller cred already
 * overridden by the worker - never with a kworker's own creds. */
static int susfs_resolve_app_uid(const char *app_name, uid_t *uid)
{
	struct file *fp;
	char *buf = NULL;
	char *line, *tmp, *p;
	char *pkg_name, *uid_str;
	loff_t pos = 0;
	size_t size;
	unsigned long val;
	int ret = -ENOENT;

	if (!app_name || !*app_name || !uid)
		return -EINVAL;
	if (!susfs_is_valid_app_name(app_name))
		return -EINVAL;

	fp = filp_open(SUSFS_PACKAGES_LIST_PATH, O_RDONLY | O_NOATIME, 0);
	if (IS_ERR(fp)) {
		ret = PTR_ERR(fp);
		pr_err("susfs_guard_lkm: failed to open %s: %d\n",
		       SUSFS_PACKAGES_LIST_PATH, ret);
		return ret;
	}

	size = i_size_read(file_inode(fp));
	if (size <= 0 || size > SUSFS_PACKAGES_LIST_MAX_SIZE) {
		fput(fp);
		return -EFBIG;
	}

	buf = vmalloc(size + 1);
	if (!buf) {
		fput(fp);
		return -ENOMEM;
	}
	buf[size] = '\0';

	ret = kernel_read(fp, buf, size, &pos);
	fput(fp);
	if (ret != (int)size) {
		vfree(buf);
		return -EIO;
	}

	line = buf;
	while (line && *line) {
		p = strchr(line, '\n');
		if (p) {
			*p = '\0';
			tmp = p + 1;
		} else {
			tmp = NULL;
		}
		if (*line == '\0' || *line == '\r') {
			line = tmp;
			continue;
		}
		/* packages.list format: <package> <uid> <gid> ... */
		pkg_name = strsep(&line, " \t");
		if (!pkg_name || *pkg_name == '\0') {
			line = tmp;
			continue;
		}
		uid_str = strsep(&line, " \t");
		if (!uid_str || *uid_str == '\0') {
			line = tmp;
			continue;
		}
		if (!strcmp(pkg_name, app_name)) {
			if (susfs_parse_ulong(uid_str, &val)) {
				vfree(buf);
				return -EINVAL;
			}
			*uid = (uid_t)(val % 100000);
			vfree(buf);
			if (*uid < SUSFS_UID_FILTER_MIN_UID ||
			    *uid > SUSFS_UID_FILTER_MAX_UID)
				return -EINVAL;
			return 0;
		}
		line = tmp;
	}

	vfree(buf);
	return -ENOENT;
}

static int susfs_parse_app_names(char *app_str, unsigned long *bits,
				 bool skip_failed)
{
	char *token = NULL;
	char *saveptr = app_str;
	uid_t uid = 0;
	int ret;

	while ((token = strsep(&saveptr, ",")) != NULL) {
		token = strim(token);
		if (*token == '\0')
			continue;
		if (!susfs_is_valid_app_name(token)) {
			pr_err("susfs_guard_lkm: invalid app name '%s'\n", token);
			return -EINVAL;
		}
		ret = susfs_resolve_app_uid(token, &uid);
		if (ret) {
			if (skip_failed)
				continue;
			return ret;
		}
		if (uid < SUSFS_UID_FILTER_MIN_UID ||
		    uid > SUSFS_UID_FILTER_MAX_UID) {
			pr_err("susfs_guard_lkm: uid %u of app '%s' out of range [%d, %d]\n",
			       uid, token, SUSFS_UID_FILTER_MIN_UID,
			       SUSFS_UID_FILTER_MAX_UID);
			if (!skip_failed)
				return -EINVAL;
			continue;
		}
		set_bit(uid - SUSFS_UID_FILTER_MIN_UID, bits);
		SUSFS_LOGI("susfs uid filter: app '%s', uid '%u' added\n",
			   token, uid);
	}
	return 0;
}

/*
 * 6.12 removed direct access to inode->i_mtime (timestamps are now kept as
 * separate sec/nsec fields); the inode_get_mtime() accessor exists from 6.11.
 * Older kernels still use the struct field directly.
 */
static struct timespec64 susfs_uid_filter_get_mtime(struct inode *inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
	return inode_get_mtime(inode);
#else
	return inode->i_mtime;
#endif
}

/* Open packages.list and snapshot its mtime + size; false when it cannot be
 * opened.  The two callers below differ only in what they do with the
 * snapshot, so the open/read/close lives here once. */
static bool susfs_uid_filter_stat_list(struct timespec64 *mtime, loff_t *size)
{
	struct file *fp = filp_open(SUSFS_PACKAGES_LIST_PATH,
				     O_RDONLY | O_NOATIME, 0);

	if (IS_ERR(fp))
		return false;
	*mtime = susfs_uid_filter_get_mtime(file_inode(fp));
	*size = i_size_read(file_inode(fp));
	fput(fp);
	return true;
}

/* Snapshot packages.list's mtime/size, for the delayed re-check. */
static void susfs_uid_filter_note_mtime(struct susfs_uid_filter *f)
{
	struct timespec64 mtime;
	loff_t size;

	if (!susfs_uid_filter_stat_list(&mtime, &size))
		return;
	f->last_mtime_sec = mtime.tv_sec;
	f->last_mtime_nsec = mtime.tv_nsec;
	f->last_size = size;
	f->have_mtime = true;
}

static bool susfs_uid_filter_mtime_changed(struct susfs_uid_filter *f)
{
	struct timespec64 mtime;
	loff_t size;

	if (!f->have_mtime)
		return true;
	if (!susfs_uid_filter_stat_list(&mtime, &size))
		return false;
	return (mtime.tv_sec != f->last_mtime_sec ||
		mtime.tv_nsec != f->last_mtime_nsec ||
		size != f->last_size);
}

static void susfs_uid_filter_save_caller_cred(struct susfs_uid_filter *f)
{
	const struct cred *new = get_cred(current_cred());
	const struct cred *old;

	mutex_lock(&f->cred_lock);
	old = f->caller_cred;
	f->caller_cred = new;
	mutex_unlock(&f->cred_lock);
	if (old)
		put_cred(old);
}

/* Returns the cred revert_creds() wants; @borrowed holds the reference this
 * call took (same pattern as sus_path_override_creds() in sus_path.c). */
static const struct cred *
susfs_uid_filter_override_creds(struct susfs_uid_filter *f,
				const struct cred **borrowed)
{
	const struct cred *cred;

	*borrowed = NULL;
	mutex_lock(&f->cred_lock);
	cred = f->caller_cred;
	if (cred)
		get_cred(cred);
	mutex_unlock(&f->cred_lock);
	if (!cred)
		return NULL;
	*borrowed = cred;
	return override_creds(cred);
}

static void susfs_uid_filter_revert_creds(const struct cred *saved,
					  const struct cred *borrowed)
{
	if (saved)
		revert_creds(saved);
	if (borrowed)
		put_cred(borrowed);
}

static void susfs_uid_filter_publish(struct susfs_uid_filter *f,
				     struct susfs_uid_filter_bitmap *new_bitmap,
				     char *new_app_strings)
{
	struct susfs_uid_filter_bitmap *old_bitmap;

	mutex_lock(&f->lock);
	old_bitmap = rcu_dereference_protected(f->bitmap,
					       lockdep_is_held(&f->lock));
	rcu_assign_pointer(f->bitmap, new_bitmap);
	if (new_app_strings) {
		kvfree(f->app_strings);
		f->app_strings = new_app_strings;
	}
	mutex_unlock(&f->lock);
	synchronize_rcu();
	kfree_rcu(old_bitmap, rcu);
}

/* Shared setter body: both payload structs are char[65535] + int err, with
 * err at offset 65536 (C pads the int to a 4-byte boundary, sizeof 65540) -
 * the same layout upstream's kernel and ksu_susfs tool use. */
static int susfs_uid_filter_set(struct susfs_uid_filter *f,
				void __user **arg, const char *cmd_name)
{
	struct st_susfs_sus_path_uid_filter *info = NULL;
	struct susfs_uid_filter_bitmap *new_bitmap = NULL;
	char *new_app_strings = NULL;
	size_t app_str_len = 0;
	int err = 0;
	static bool warned_once;

	/* The payload is 64 KiB - never on the stack. */
	info = kvmalloc(sizeof(*info), GFP_KERNEL | __GFP_ZERO);
	if (!info) {
		err = -ENOMEM;
		goto out_copy_to_user;
	}
	if (copy_from_user(info, *arg, sizeof(*info))) {
		err = -EFAULT;
		goto out_copy_to_user;
	}
	if (!memchr(info->app_strings, '\0', sizeof(info->app_strings))) {
		pr_err("susfs_guard_lkm: %s: app names not null terminated\n",
		       cmd_name);
		err = -EINVAL;
		goto out_copy_to_user;
	}
	if (*info->app_strings == '\0') {
		pr_err("susfs_guard_lkm: %s: app names cannot be empty\n",
		       cmd_name);
		err = -EINVAL;
		goto out_copy_to_user;
	}
	app_str_len = strlen(info->app_strings);
	new_app_strings = kvmalloc(app_str_len + 1, GFP_KERNEL | __GFP_ZERO);
	if (!new_app_strings) {
		err = -ENOMEM;
		goto out_copy_to_user;
	}
	memcpy(new_app_strings, info->app_strings, app_str_len + 1);

	new_bitmap = kzalloc(sizeof(*new_bitmap), GFP_KERNEL);
	if (!new_bitmap) {
		err = -ENOMEM;
		goto out_free_new_app_strings;
	}

	/* Runs in the supercall's task_work, with ksud's credentials: read
	 * packages.list directly, no cred switch. */
	susfs_uid_filter_save_caller_cred(f);
	err = susfs_parse_app_names(info->app_strings, new_bitmap->bits, true);
	if (err)
		goto out_free_new_bitmap;

	susfs_uid_filter_publish(f, new_bitmap, new_app_strings);
	new_bitmap = NULL;
	new_app_strings = NULL;
	susfs_uid_filter_note_mtime(f);
	SUSFS_LOGI("susfs uid filter: %s set (%s)\n", cmd_name, f->label);
	err = 0;

out_free_new_bitmap:
	if (new_bitmap)
		kfree(new_bitmap);
out_free_new_app_strings:
	if (new_app_strings)
		kvfree(new_app_strings);
out_copy_to_user:
	if (copy_to_user((char __user *)*arg +
			 offsetof(struct st_susfs_sus_path_uid_filter, err),
			 &err, sizeof(err)))
		err = -EFAULT;
	if (!warned_once && err) {
		warned_once = true;
		pr_warn("susfs_guard_lkm: %s -> ret: %d\n", cmd_name, err);
	}
	if (info)
		kvfree(info);
	return err;
}

void susfs_set_sus_path_uid_filter_supercall(void __user **arg)
{
	susfs_uid_filter_set(&sus_path_filter, arg,
			     "CMD_SUSFS_SET_SUS_PATH_UID_FILTER");
}

void susfs_set_priority_uid_filter_supercall(void __user **arg)
{
	susfs_uid_filter_set(&priority_filter, arg,
			     "CMD_SUSFS_SET_PRIORITY_UID_FILTER");
}

/* Re-resolve worker: same parse, under the saved caller cred. */
static int susfs_uid_filter_worker(void *data)
{
	struct susfs_uid_filter *f = data;
	struct susfs_uid_filter_bitmap *new_bitmap = NULL;
	struct susfs_uid_filter_bitmap *old_bitmap = NULL;
	const struct cred *saved = NULL, *borrowed = NULL;
	char *app_strings = NULL;
	size_t app_str_len = 0;
	int ret = 0;

	mutex_lock(&f->lock);
	if (f->app_strings) {
		app_str_len = strlen(f->app_strings);
		app_strings = kvmalloc(app_str_len + 1, GFP_KERNEL | __GFP_ZERO);
		if (app_strings)
			memcpy(app_strings, f->app_strings, app_str_len + 1);
	}
	mutex_unlock(&f->lock);
	if (!app_strings)
		goto out;

	new_bitmap = kzalloc(sizeof(*new_bitmap), GFP_KERNEL);
	if (!new_bitmap)
		goto out;

	saved = susfs_uid_filter_override_creds(f, &borrowed);
	ret = susfs_parse_app_names(app_strings, new_bitmap->bits, true);
	susfs_uid_filter_revert_creds(saved, borrowed);
	if (ret)
		goto out;

	mutex_lock(&f->lock);
	old_bitmap = rcu_dereference_protected(f->bitmap,
					       lockdep_is_held(&f->lock));
	rcu_assign_pointer(f->bitmap, new_bitmap);
	new_bitmap = NULL;
	mutex_unlock(&f->lock);
	synchronize_rcu();
	kfree_rcu(old_bitmap, rcu);
	susfs_uid_filter_note_mtime(f);
	SUSFS_LOGI("susfs uid filter: %s re-resolved\n", f->label);

out:
	if (new_bitmap)
		kfree(new_bitmap);
	if (app_strings)
		kvfree(app_strings);
	atomic_set(&f->running, 0);
	return ret;
}

static void susfs_uid_filter_parse(struct susfs_uid_filter *f,
				   const char *thread_name)
{
	if (atomic_cmpxchg(&f->running, 0, 1))
		return;
	if (IS_ERR(kthread_run(susfs_uid_filter_worker, f, "%s", thread_name))) {
		atomic_set(&f->running, 0);
		pr_err("susfs_guard_lkm: failed to create thread %s\n",
		       thread_name);
	}
}

void susfs_parse_sus_path_app_strings(void)
{
	susfs_uid_filter_parse(&sus_path_filter, "susfs_spuid_appstr");
}

void susfs_parse_priority_app_strings(void)
{
	susfs_uid_filter_parse(&priority_filter, "susfs_gpsp_appstr");
}

/* Upstream fs/susfs.c, verbatim semantics (see the header comment). */
bool susfs_is_uid_allowed_for_sus_path(uid_t uid)
{
	struct susfs_uid_filter_bitmap *bitmap;

	if (uid >= 90000)
		return true;
	if (uid < SUSFS_UID_FILTER_MIN_UID ||
	    uid > SUSFS_UID_FILTER_MAX_UID)
		return false;
	rcu_read_lock();
	bitmap = rcu_dereference(sus_path_filter.bitmap);
	if (likely(bitmap)) {
		if (test_bit(uid - SUSFS_UID_FILTER_MIN_UID, bitmap->bits)) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

bool susfs_is_priority_uid_filtered(uid_t uid)
{
	struct susfs_uid_filter_bitmap *bitmap;
	uid_t app_id = uid % 100000;
	bool filtered = false;

	if (app_id < SUSFS_UID_FILTER_MIN_UID ||
	    app_id > SUSFS_UID_FILTER_MAX_UID)
		return false;
	rcu_read_lock();
	bitmap = rcu_dereference(priority_filter.bitmap);
	if (likely(bitmap))
		filtered = test_bit(app_id - SUSFS_UID_FILTER_MIN_UID,
				    bitmap->bits);
	rcu_read_unlock();
	return filtered;
}

static void susfs_uid_filter_recheck_fn(struct work_struct *work)
{
	struct susfs_uid_filter *filters[] = { &sus_path_filter,
						&priority_filter };
	int i;

	for (i = 0; i < ARRAY_SIZE(filters); i++) {
		struct susfs_uid_filter *f = filters[i];

		mutex_lock(&f->lock);
		if (!f->app_strings) {
			mutex_unlock(&f->lock);
			continue;
		}
		mutex_unlock(&f->lock);
		if (susfs_uid_filter_mtime_changed(f))
			susfs_uid_filter_parse(f, f == &sus_path_filter ?
					       "susfs_spuid_appstr" :
					       "susfs_gpsp_appstr");
	}
	if (susfs_uid_filter_inited)
		schedule_delayed_work(&susfs_uid_filter_recheck_work,
				      msecs_to_jiffies(SUSFS_UID_FILTER_RECHECK_MS));
}

static void susfs_uid_filter_init_one(struct susfs_uid_filter *f,
				      const char *label)
{
	memset(f, 0, sizeof(*f));
	mutex_init(&f->lock);
	mutex_init(&f->cred_lock);
	atomic_set(&f->running, 0);
	f->label = label;
}

int susfs_uid_filter_init(void)
{
	int rc;

	susfs_uid_filter_init_one(&sus_path_filter, "sus_path");
	susfs_uid_filter_init_one(&priority_filter, "priority");
	INIT_DELAYED_WORK(&susfs_uid_filter_recheck_work,
			  susfs_uid_filter_recheck_fn);
	susfs_uid_filter_inited = true;
	schedule_delayed_work(&susfs_uid_filter_recheck_work,
			      msecs_to_jiffies(SUSFS_UID_FILTER_RECHECK_MS));
	/* Non-fatal: if the table entries cannot be patched the setters still
	 * work and the module still loads - the priority filter just stays
	 * inert until the hook is there. */
	rc = susfs_priority_hook_init();
	if (rc)
		pr_warn("susfs uid filter: priority hook not armed (%d)\n", rc);
	return 0;
}

static void susfs_uid_filter_exit_one(struct susfs_uid_filter *f)
{
	struct susfs_uid_filter_bitmap *bitmap;
	const struct cred *cred;
	int waited = 0;

	/* A worker holds no reference to this struct after it returns; wait
	 * briefly for one that is already running before freeing. */
	while (atomic_read(&f->running) && waited < 250) {
		msleep(20);
		waited++;
	}
	mutex_lock(&f->lock);
	bitmap = rcu_dereference_protected(f->bitmap,
					   lockdep_is_held(&f->lock));
	RCU_INIT_POINTER(f->bitmap, NULL);
	kvfree(f->app_strings);
	f->app_strings = NULL;
	mutex_unlock(&f->lock);
	synchronize_rcu();
	kfree(bitmap);

	mutex_lock(&f->cred_lock);
	cred = f->caller_cred;
	f->caller_cred = NULL;
	mutex_unlock(&f->cred_lock);
	if (cred)
		put_cred(cred);
}

void susfs_uid_filter_exit(void)
{
	susfs_uid_filter_inited = false;
	cancel_delayed_work_sync(&susfs_uid_filter_recheck_work);
	/* Remove the hook first and drain in-flight wrappers before the
	 * bitmaps they read can go away. */
	susfs_priority_hook_exit();
	susfs_uid_filter_exit_one(&sus_path_filter);
	susfs_uid_filter_exit_one(&priority_filter);
}
