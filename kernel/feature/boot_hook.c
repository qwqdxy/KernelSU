// SPDX-License-Identifier: GPL-2.0
/*
 * boot_hook.c -- late-load 模式下的「框架重启」钩子
 *
 * 背景：
 *   KernelSU 在 late-load 模式下没有 initrc/preinit，模块脚本只在
 *   ksud late-load 那一刻跑一次。软重启（zygote/system_server 重启）
 *   之后没人再去跑它们，procfs 的 chmod 封锁在 inode 被回收后会失效。
 *
 * 抓时机：
 *   init 启动 zygote 时 exec /system/bin/app_process（之后用 argv 改写
 *   显示成 zygote64）。无论是开机、stop/start 还是 ctl.restart zygote，
 *   zygote 每次重启都会重新 exec 它 → kprobe 在 do_execveat_common 上命中。
 *
 * 做什么（关键）：
 *   直接在内核里改 inode 的 i_mode —— 不走 userspace，不受 SELinux 约束，
 *   不 fork 进程。之前试过 call_usermodehelper 拉脚本，rc=0 但 chmod
 *   被内核域的限制静默拒绝。
 *
 * 顺带：
 *   仍然尝试用 usermodehelper 跑一遍模块的 post-mount.sh，负责属性类
 *   的操作（属性在软重启后不会丢，所以这一步是锦上添花）。
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
#define BOOT_HOOK_GAP (5 * HZ)

struct boot_hook_lock {
	const char *path;
	umode_t mode;
};

static const struct boot_hook_lock boot_hook_locks[] = {
	{ "/proc/modules", 0000 },
	{ "/proc/kallsyms", 0000 },
	{ "/proc/cmdline", 0440 },
	{ "/proc/net/unix", 0440 },
	{ "/sys/fs/selinux/enforce", 0640 },
	{ "/sys/fs/selinux/policy", 0440 },
};

static unsigned long boot_hook_last;

static int boot_hook_apply_one(const char *path, umode_t mode)
{
	struct path p;
	struct inode *inode;

	if (kern_path(path, LOOKUP_FOLLOW, &p))
		return -ENOENT;

	inode = d_backing_inode(p.dentry);
	if (inode) {
		inode_lock(inode);
		inode->i_mode = (inode->i_mode & ~0777) | (mode & 0777);
		inode_unlock(inode);
		pr_info("boot_hook: lock %s -> %04o\n", path, mode);
	}
	path_put(&p);
	return 0;
}

static void boot_hook_apply_all(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(boot_hook_locks); i++)
		boot_hook_apply_one(boot_hook_locks[i].path,
				    boot_hook_locks[i].mode);
}

static void boot_hook_run(struct work_struct *w)
{
	static char *envp[] = { "PATH=/system/bin:/data/adb/ksu/bin",
				"HOME=/", NULL };
	static char *script_argv[] = { "/system/bin/sh", BOOT_HOOK_SCRIPT, NULL };

	/* 内核侧直接改权限：这是真正生效的手段 */
	boot_hook_apply_all();

	/* userspace 脚本：负责属性等（失败也无所谓） */
	(void)call_usermodehelper(script_argv[0], script_argv, envp,
				  UMH_WAIT_EXEC);
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
	if (boot_hook_last && time_before(now, boot_hook_last + BOOT_HOOK_GAP))
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
	pr_info("boot_hook: watching app_process, %d lock targets\n",
		(int)ARRAY_SIZE(boot_hook_locks));
}

void __exit ksu_boot_hook_exit(void)
{
	if (boot_hook_registered) {
		unregister_kprobe(&boot_hook_kp);
		boot_hook_registered = false;
	}
	cancel_work_sync(&boot_hook_work);
}
