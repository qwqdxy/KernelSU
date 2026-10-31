// SPDX-License-Identifier: GPL-2.0
/*
 * boot_hook.c -- late-load 模式下的「框架重启」钩子 + 内核级权限维护
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
 * 三件事：
 *   1) 内核直接改 inode->i_mode 锁关键文件（用户态 chmod 有些路径 EPERM）
 *   2) 内核直接隐藏指定进程（用户态 chmod /proc/<pid> 必 EPERM）
 *   3) 以 u:r:ksu:s0 域拉起模块脚本（关键：usermodehelper 默认跑在受限域，
 *      chmod/resetprop/insmod 全都会失败；用 call_usermodehelper_setup 的
 *      init 回调把新进程的 cred 转到 ksu 域，脚本就有完整权限了）
 */

#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/umh.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <linux/jiffies.h>

#include "selinux/selinux.h"

#define BOOT_HOOK_SCRIPT "/data/adb/modules/m_rcq/post-mount.sh"
#define BOOT_HOOK_GAP (5 * HZ)
#define BOOT_HOOK_MAX_HIDE 128

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
	{ "/data/adb", 0700 },
	{ "/sys/kernel/debug", 0000 },
	{ "/sys/kernel/debug/tracing", 0000 },
	{ "/proc/ksu", 0000 },
};

static const char *const boot_hook_hide_names[] = {
	"magisk", "magiskd", "su", "ksu", "ksud", "kernelsu", "ksuhelper",
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

static void boot_hook_hide_procs(void)
{
	int pids[BOOT_HOOK_MAX_HIDE];
	int n = 0, i, j;
	struct task_struct *task;

	rcu_read_lock();
	for_each_process(task) {
		if (n >= BOOT_HOOK_MAX_HIDE)
			break;
		for (j = 0; j < ARRAY_SIZE(boot_hook_hide_names); j++) {
			if (!strcmp(task->comm, boot_hook_hide_names[j])) {
				pids[n++] = task->pid;
				break;
			}
		}
	}
	rcu_read_unlock();

	for (i = 0; i < n; i++) {
		char path[32];

		snprintf(path, sizeof(path), "/proc/%d", pids[i]);
		boot_hook_apply_one(path, 0000);
	}
	if (n)
		pr_info("boot_hook: hid %d process(es)\n", n);
}

/* 把新进程的 cred 转到 u:r:ksu:s0，脚本才有完整权限 */
static int boot_hook_umh_init(struct subprocess_info *info, struct cred *new)
{
	setup_selinux(KERNEL_SU_CONTEXT, new);
	return 0;
}

static int boot_hook_exec_script(char **argv, char **envp)
{
	struct subprocess_info *info;
	int rc;

	info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,
					 boot_hook_umh_init, NULL, NULL);
	if (!info)
		return -ENOMEM;
	rc = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
	return rc;
}

static void boot_hook_run(struct work_struct *w)
{
	static char *envp[] = { "PATH=/system/bin:/data/adb/ksu/bin",
				"HOME=/", NULL };
	/*
	 * 直接跑模块的 service.sh，而不是 `ksud services`：
	 * ksud 的 services 阶段有 report_services() 一次性检查，
	 * 每次 LKM 加载只放行一次，第二次就 "already started, skipping"。
	 * service.sh 自身幂等（check_reset_prop 会跳过已正确的值）。
	 */
	static char *svc_argv[] = { "/system/bin/sh",
				    "/data/adb/modules/m_rcq/service.sh", NULL };
	int rc;

	boot_hook_apply_all();
	boot_hook_hide_procs();

	/* 以 ksu 域跑模块脚本（属性/susfs/其他封锁） */
	rc = boot_hook_exec_script(svc_argv, envp);
	pr_info("boot_hook: service.sh rc=%d\n", rc);
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
	pr_info("boot_hook: %d locks, %d hide names, ksu-domain script\n",
		(int)ARRAY_SIZE(boot_hook_locks),
		(int)ARRAY_SIZE(boot_hook_hide_names));
}

void __exit ksu_boot_hook_exit(void)
{
	if (boot_hook_registered) {
		unregister_kprobe(&boot_hook_kp);
		boot_hook_registered = false;
	}
	cancel_work_sync(&boot_hook_work);
}
