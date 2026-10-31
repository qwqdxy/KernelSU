// SPDX-License-Identifier: GPL-2.0
/*
 * boot_hook.c -- late-load 模式下的「框架重启」钩子
 *
 * kprobe on do_execveat_common，命中 app_process / system_server 时
 * 用 call_usermodehelper 拉起 RCQ 的封锁脚本。
 *
 * 本版本是诊断版：
 *   1. 先用 UMH_WAIT_PROC 执行一条只写 /dev/kmsg 的命令（不碰任何文件），
 *      验证 usermodehelper 本身是否正常。
 *   2. 再用 UMH_WAIT_PROC 执行脚本，并把进程退出码打进内核日志。
 */

#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/umh.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/jiffies.h>

#define BOOT_HOOK_SCRIPT "/data/adb/modules/m_rcq/post-mount.sh"
#define BOOT_HOOK_PATH "/proc/modules"
#define BOOT_HOOK_MIN_GAP (5 * HZ)

static unsigned long boot_hook_last;

static bool boot_hook_locked(void)
{
	struct path path;
	umode_t mode;

	if (kern_path(BOOT_HOOK_PATH, LOOKUP_FOLLOW, &path))
		return false;
	if (!path.dentry || !d_backing_inode(path.dentry)) {
		path_put(&path);
		return false;
	}
	mode = d_backing_inode(path.dentry)->i_mode;
	path_put(&path);
	return (mode & 0777) == 0;
}

static void boot_hook_run(struct work_struct *w)
{
	static char *envp[] = { "PATH=/system/bin:/data/adb/ksu/bin",
				"HOME=/", NULL };
	/* 阶段1：完全不读任何文件，只写 kmsg */
	static char *mark_argv[] = {
		"/system/bin/sh", "-c",
		"echo BOOT_HOOK_MARKER_CTX=$(cat /proc/self/attr/current 2>/dev/null) > /dev/kmsg",
		NULL
	};
	/* 阶段2：真正执行脚本，并记录退出码 */
	static char *script_argv[] = {
		"/system/bin/sh", "-c",
		"echo BOOT_HOOK_START > /dev/kmsg;"
		"sh " BOOT_HOOK_SCRIPT " > /dev/kmsg 2>&1;"
		"echo BOOT_HOOK_END rc=$? modules=$(ls -ld /proc/modules 2>&1) > /dev/kmsg",
		NULL
	};
	int rc;

	rc = call_usermodehelper(mark_argv[0], mark_argv, envp, UMH_WAIT_PROC);
	pr_info("boot_hook: marker rc=%d\n", rc);

	if (boot_hook_locked()) {
		pr_info("boot_hook: already locked, skip\n");
		return;
	}
	rc = call_usermodehelper(script_argv[0], script_argv, envp, UMH_WAIT_PROC);
	pr_info("boot_hook: script rc=%d\n", rc);
}
static DECLARE_WORK(boot_hook_work, boot_hook_run);

static bool boot_hook_match(const char *path)
{
	const char *base;

	if (!path)
		return false;
	base = strrchr(path, '/');
	base = base ? base + 1 : path;
	if (!strcmp(base, "app_process") || !strcmp(base, "app_process64") ||
	    !strcmp(base, "app_process32") || !strcmp(base, "system_server"))
		return true;
	return false;
}

static int boot_hook_exec_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct filename *fn;
	unsigned long now;

#if defined(__aarch64__)
	fn = (struct filename *)regs->regs[1];
#elif defined(__x86_64__)
	fn = (struct filename *)(uintptr_t)regs->si;
#elif defined(__riscv)
	fn = (struct filename *)(uintptr_t)regs->a1;
#else
	fn = NULL;
#endif
	if (!fn || (unsigned long)fn < 4096)
		return 0;
	if (!boot_hook_match(fn->name))
		return 0;

	now = jiffies;
	if (boot_hook_last && time_before(now, boot_hook_last + BOOT_HOOK_MIN_GAP))
		return 0;
	boot_hook_last = now;

	schedule_work(&boot_hook_work);
	return 0;
}

static struct kprobe boot_hook_kp = {
	.symbol_name = "do_execveat_common",
	.pre_handler = boot_hook_exec_pre,
};

static bool boot_hook_registered;

void __init ksu_boot_hook_init(void)
{
	int rc = register_kprobe(&boot_hook_kp);

	if (rc) {
		pr_warn("boot_hook: register_kprobe failed: %d\n", rc);
		return;
	}
	boot_hook_registered = true;
	pr_info("boot_hook: watching app_process -> " BOOT_HOOK_SCRIPT "\n");
}

void __exit ksu_boot_hook_exit(void)
{
	if (boot_hook_registered) {
		unregister_kprobe(&boot_hook_kp);
		boot_hook_registered = false;
	}
	cancel_work_sync(&boot_hook_work);
}
