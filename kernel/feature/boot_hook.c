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
 * 做什么：
 *   全部在内核里直接改 inode->i_mode，不走 userspace：
 *     1) 锁 procfs/sysfs 关键文件
 *     2) 隐藏指定名字的进程（RCQ 的 HIDE_PROCS，用户态 chmod 会 EPERM）
 *     3) /sys/kernel/debug 这种 debugfs 挂载点，用户态 chmod 也 EPERM
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

#define BOOT_HOOK_SCRIPT "/data/adb/modules/m_rcq/post-mount.sh"
#define BOOT_HOOK_GAP (5 * HZ)
#define BOOT_HOOK_MAX_HIDE 128

struct boot_hook_lock {
	const char *path;
	umode_t mode;
};

/*
 * 注意顺序：/data/adb 必须是 0700，否则 ksud 装模块时会被重置成 0777。
 * /sys/kernel/debug 是 debugfs 挂载点，用户态 chmod 报 EPERM，
 * 只有内核直接改 inode 才有效。
 */
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

/* RCQ service.sh 的 HIDE_PROCS 列表 */
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

/*
 * HIDE_PROCS：用户态 chmod 000 /proc/<pid> 会 EPERM
 * （procfs 的 proc_pid_permission 拒绝 setattr），
 * 内核直接改 inode 就绕过了那个检查。
 */
static void boot_hook_hide_procs(void)
{
	int pids[BOOT_HOOK_MAX_HIDE];
	int n = 0, i, j;
	struct task_struct *task;

	/* RCU 段内不能调 kern_path（会睡），只收集 pid */
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

static void boot_hook_run(struct work_struct *w)
{
	static char *envp[] = { "PATH=/system/bin:/data/adb/ksu/bin",
				"HOME=/", NULL };
	static char *script_argv[] = { "/system/bin/sh", BOOT_HOOK_SCRIPT, NULL };

	/* 内核侧：锁文件 + 隐藏进程，这两件事用户态做不到 */
	boot_hook_apply_all();
	boot_hook_hide_procs();

	/* userspace 脚本：只负责属性等（chmod 会被 SELinux 拒，没关系） */
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
	pr_info("boot_hook: watching app_process, %d locks, %d hide names\n",
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
