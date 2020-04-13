#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/spinlock.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>

void sched_halt(void);

// Choose a user environment to run and run it.
void
sched_yield(void)
{
	struct Env *idle;

	// Implement simple round-robin scheduling.
	//
	// Search through 'envs' for an ENV_RUNNABLE environment in
	// circular fashion starting just after the env this CPU was
	// last running.  Switch to the first such environment found.
	//
	// If no envs are runnable, but the environment previously
	// running on this CPU is still ENV_RUNNING, it's okay to
	// choose that environment.
	//
	// Never choose an environment that's currently running on
	// another CPU (env_status == ENV_RUNNING). If there are
	// no runnable environments, simply drop through to the code
	// below to halt the cpu.

	// LAB 4: Your code here.
	// 这是进程调度函数,首先我们要考虑这个特殊情况,当前还没有进程正在执行,此时curenv为0
	// 我们从进程列表的开头开始搜索,找到一个RUNNABLE的进程并执行它
	// 如果当前有进程正在执行,那么就从该进程开始,扫到进程列表的最后,然后从进程列表的开始扫到该进程的位置
	// 找到一个可以运行的进程并执行它,如果没有的话
	// 我们就判断当前正在执行的进程是否还是RUNNING的(这个不是应该一定是RUNNING吗)
	// 如果是RUNNING的话,我们就让这个进程接着执行
	// 不然的话,就意味着没有可以执行的进程了,那么我们使用sched_halt来处理它
	if(curenv == 0) {
		idle = envs;
		for(; idle < envs + NENV; idle++) {
			if(idle->env_status == ENV_RUNNABLE) {
				env_run(idle);
			}
		}
	} else {
		idle = curenv + 1;
		for(; idle < envs + NENV; idle++) {
			if(idle->env_status == ENV_RUNNABLE) {
				// cprintf("new env id is %x\n", idle->env_id);
				// 那么这个idle就是我们需要调度执行的进程
				env_run(idle);
			}
		}
		for(idle = envs; idle < curenv; idle++) {
			if(idle->env_status == ENV_RUNNABLE) {
				env_run(idle);
			}
		}
		if(curenv->env_status == ENV_RUNNING) {
			env_run(curenv);
			// 注意这里不能够return 应该调用env_run来重新启动当前进程
			// 由于这里是在中断里面的,所以curenv的tf字段中保存着中断时的断点
			// 使用env_run正好可以根据该断点实现中断的返回
		}
	}

	// sched_halt never returns
	sched_halt();
}

// Halt this CPU when there is nothing to do. Wait until the
// timer interrupt wakes it up. This function never returns.
//
void
sched_halt(void)
{
	int i;

	// For debugging and testing purposes, if there are no runnable
	// environments in the system, then drop into the kernel monitor.
	for (i = 0; i < NENV; i++) {
		if ((envs[i].env_status == ENV_RUNNABLE ||
		     envs[i].env_status == ENV_RUNNING ||
		     envs[i].env_status == ENV_DYING))
			break;
	}
	if (i == NENV) {
		cprintf("No runnable environments in the system!\n");
		while (1)
			monitor(NULL);
	}

	// Mark that no environment is running on this CPU
	curenv = NULL;
	lcr3(PADDR(kern_pgdir));

	// Mark that this CPU is in the HALT state, so that when
	// timer interupts come in, we know we should re-acquire the
	// big kernel lock
	xchg(&thiscpu->cpu_status, CPU_HALTED);

	// Release the big kernel lock as if we were "leaving" the kernel
	unlock_kernel();

	// Reset stack pointer, enable interrupts and then halt.
	asm volatile (
		"movl $0, %%ebp\n"
		"movl %0, %%esp\n"
		"pushl $0\n"
		"pushl $0\n"
		// Uncomment the following line after completing exercise 13
		"sti\n"
		"1:\n"
		"hlt\n"
		"jmp 1b\n"
	: : "a" (thiscpu->cpu_ts.ts_esp0));
}

