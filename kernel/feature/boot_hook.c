// SPDX-License-Identifier: GPL-2.0
/*
 * boot_hook.c -- 在 late-load 模式下补一个「框架重启」钩子
 *
 * 为什么需要：
 *   KernelSU 处于 late-load 模式时没有 initrc 注入、没有 preinit、
 *   模块脚本只在 ksud late-load 那一刻被调用一次。
 *   软重启（zygote/system_server 重启）之后不会有任何东西再去跑它们，
 *   于是 RCQ 施加的 procfs 封锁（chmod 000 /proc/modules 等）在 inode
 *   被回收后就会失效。
 *
 * 怎么抓：
 *   init 启动 zygote 时 exec 的是 /system/bin/app_process（之后用 argv
 *   改写把名字显示成 zygote64）。无论是开机、stop/start 还是
 *   ctl.restart zygote，zygote 每次重启都会重新 exec 它。
 *   所以在 do_execveat_common 上挂 kprobe，命中 app_process 就说明
 *   框架（重新）启动了。
 *
 * 做什么：
 *   用 call_usermodehelper 以 root 拉起
 *   /data/adb/modules/m_rcq/post-mount.sh，把封锁补回去。
 *   不能在 kprobe 上下文里直接调用，所以走 workqueue 延后到进程上下文。
 *
 * 防抖动：
 *   app_process 不只在 zygote 启动时被 exec —— settings/am/pm 这类
 *   工具也是用它跑的。所以触发前先看 /proc/modules 是不是已经 000，
 *   已经是就直接跳过，避免每次跑命令都拉起一遍脚本。
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
#define BOOT_HOOK_MIN_GAP (5 * HZ) /* 至少间隔 5 秒，防抖 */

static unsigned long boot_hook_last;

/* /proc/modules 的权限是不是已经被改成 000 了 */
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
	static char *argv[] = { "/system/bin/sh", BOOT_HOOK_SCRIPT, NULL };
	static char *envp[] = { "PATH=/system/bin:/data/adb/ksu/bin",
				"HOME=/", NULL };
	int rc;

	if (boot_hook_locked()) {
		pr_info("boot_hook: already locked, skip\n");
		return;
	}
	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	pr_info("boot_hook: reapply rc=%d\n", rc);
}
static DECLARE_WORK(boot_hook_work, boot_hook_run);

static bool boot_hook_match(const char *path)
{
	const char *base;

	if (!path)
		return false;
	base = strrchr(path, '/');
	base = base ? base + 1 : path;

	/* zygote 的可执行文件；部分 ROM 会直接 exec system_server */
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
	/* do_execveat_common(int fd, struct filename *filename, ...) */
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
