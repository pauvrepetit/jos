/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>
#include <kern/time.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	// LAB 3: Your code here.
	// 检查内存是否合法,不合法将终止掉该进程
	user_mem_assert(curenv, s, len, PTE_U);

	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	// LAB 4: Your code here.
	// 这个是创建一个空进程的函数
	// 我们以当前运行的进程为父进程和模板创建一个子进程
	// 把这个子进程的status设置为ENV_NOT_RUNNABLE
	// 还要根据父进程的env_tf的内容,为子进程设置env_tf,这里保存的是父进程进入中断时的断点
	// 这样的话,子进程开始执行后,就会直接回到父进程中断时的下一条指令处执行
	// 由于子进程的返回值应该是0,而返回值保存在eax中,所以我们需要把env_tf中eax寄存器对应的字段置为0
	// 那个地方的置原本是sys_exfork系统调用的调用号7(开始时没仔细分析这个问题,
	// 所以导致子进程开始后就会从sys_exofork中返回7,傻了)

	struct Env *new_env;
	int res = 0;
	res = env_alloc(&new_env, curenv->env_id);
	if(new_env->env_id == curenv->env_id) {
		return 0;
	}
	if(res == 0) {
		new_env->env_status = ENV_NOT_RUNNABLE;
		memcpy(&new_env->env_tf, &curenv->env_tf, sizeof(curenv->env_tf));
		new_env->env_tf.tf_regs.reg_eax = 0;
		// 这有个问题,上面的注释没怎么看懂啊 什么叫做tweaked so sys_exofork will appear to return 0
		// 看来这个的意思是说,我们需要把其中的一个寄存器置0,来表明子进程的返回值为0吧
		// 事实上,子进程继承了父进程的env_tf之后,当它开始执行的时候就会从父进程进入中断的那个位置的下一条指令开始
		return new_env->env_id;
	} else {
		return res;
	}
	// panic("sys_exofork not implemented");
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.

	// LAB 4: Your code here.
	// 给进程设置status字段
	if(status != ENV_RUNNABLE && status != ENV_NOT_RUNNABLE)
		return -E_INVAL;

	struct Env *env;
	int res = envid2env(envid, &env, 1);
	if(res != 0)
		return res;
	else {
		env->env_status = status;
		return 0;
	}

	// panic("sys_env_set_status not implemented");
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3), interrupts enabled, and IOPL of 0.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// LAB 5: Your code here.
	// Remember to check whether the user has supplied us with a good
	// address!
	// ? 什么叫做 用户提供了一个good的地址
	// 设置运行的特权级(也就是CS寄存器的低两位)
	// 设置允许中断 和 不允许IO(这是eflags寄存器中的几个标志位)
	// 将更新后的寄存器状态写入到进程envid的进程信息块中
	struct Env *env;
	int res = envid2env(envid, &env, 1);
	if(res < 0)
		return res;
	tf->tf_cs |= 3;
	tf->tf_eflags &= ~FL_IF;
	tf->tf_eflags &= ~FL_IOPL_MASK;
	memcpy(&env->env_tf, tf, sizeof(struct Trapframe));
	return res;
	// panic("sys_env_set_trapframe not implemented");
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	// 给进程添加page fault的处理程序,程序入口放在进程信息块中env_pgfault_upcall字段中
	struct Env *env;
	int res = envid2env(envid, &env, 1);
	if(res != 0) {
		// envid2env失败
		return res;
	} else {
		env->env_pgfault_upcall = func;
		return 0;
	}
	// panic("sys_env_set_pgfault_upcall not implemented");
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!

	// LAB 4: Your code here.
	// 为envid进程申请一个页,并将其映射到虚地址va的位置
	if((uint32_t)va >= UTOP || ((uint32_t)va & (PGSIZE - 1)) != 0) {
		return -E_INVAL;
	}
	if((perm & (PTE_P | PTE_U)) != (PTE_P | PTE_U)) {
		return -E_INVAL;
	}
	if(perm & ~PTE_SYSCALL) {
		return -E_INVAL;
	}
	struct Env *env;
	int res = envid2env(envid, &env, 1);
	if(res != 0)
		return res;
	else {
		struct PageInfo *pp = page_alloc(ALLOC_ZERO);
		if(pp == NULL)
			return -E_NO_MEM;
		else {
			res = page_insert(env->env_pgdir, pp, va, perm);
			if(res != 0)
				page_free(pp);
			return res;
		}
	}

	// panic("sys_page_alloc not implemented");
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.

	// LAB 4: Your code here.
	// 将srcenvid进程的虚地址srcva处对应的物理地址页映射到dstenvid进程的虚地址dstva处
	if((uint32_t)srcva >= UTOP || ((uint32_t)srcva & (PGSIZE - 1)) != 0) {
		return -E_INVAL;
	}
	if((uint32_t)dstva >= UTOP || ((uint32_t)dstva & (PGSIZE - 1)) != 0) {
		return -E_INVAL;
	}

	if((perm & (PTE_P | PTE_U)) != (PTE_P | PTE_U)) {
		return -E_INVAL;
	}
	if(perm & ~PTE_SYSCALL) {
		return -E_INVAL;
	}

	struct Env *src_env, *dst_env;
	pte_t *src_pte;
	int res;
	res = envid2env(srcenvid, &src_env, 1);
	if(res != 0)
		return res;
	res = envid2env(dstenvid, &dst_env, 1);
	if(res != 0)
		return res;
	struct PageInfo *pp = page_lookup(src_env->env_pgdir, srcva, &src_pte);
	if(pp == NULL) {
		return -E_INVAL;
	}
	
	if(!(*src_pte & PTE_W) && (perm & PTE_W)) {
		return -E_INVAL;
	}

	res = page_insert(dst_env->env_pgdir, pp, dstva, perm);
	return res;

	// panic("sys_page_map not implemented");
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().

	// LAB 4: Your code here.
	// 取消envid进程在虚地址va处的一个页的映射
	if((uint32_t)va >= UTOP || ((uint32_t)va & (PGSIZE - 1)) != 0)
		return -E_INVAL;

	struct Env *env;
	int res = envid2env(envid, &env, 1);
	if(res != 0)
		return res;
	page_remove(env->env_pgdir, va);
	return 0;

	// panic("sys_page_unmap not implemented");
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.

	// 首先检查envid对应的进程是否存在
	struct Env *env;
	int res = envid2env(envid, &env, 0);
	if(res != 0)
		return res;
	
	// 如果envid没有被ipc_recv锁定(也就是说,他没有调用接收函数)
	// 或者 已经有其他的进程给envid发送数据并且被它接收了
	// 此时 发送是失败的
	if(env->env_ipc_recving == 0)
		return -E_IPC_NOT_RECV;

	// 首先将env_ipc_perm置为0,如果后续需要设置它的值的话,就设置为新的值
	// 否则就保持这里赋值的0
	env->env_ipc_perm = 0;
	
	if((uint32_t)srcva < UTOP) {
		if(((uint32_t)srcva & (PGSIZE - 1)) != 0)
			return -E_INVAL;
		if((perm & (PTE_P | PTE_U)) != (PTE_P | PTE_U))
			return -E_INVAL;
		if(perm & ~PTE_SYSCALL)
			return -E_INVAL;
		pte_t pte = *pgdir_walk(curenv->env_pgdir, srcva, 0);
		if(pte == 0)
			return -E_INVAL;
		if((perm & PTE_W) && !(pte & PTE_W))
			return -E_INVAL;
		
		// 注意这里不能调用sys_page_map来实现页面映射
		// 因为sys_page_map中要求当前进程能够对对方进程的进程信息块进行修改(即需要检查权限)
		// 此处我们实际上是没有这个权限的,因此我们需要直接书写该函数中的功能,而不执行上述权限检查
		// res = sys_page_map(curenv->env_id, srcva, envid, env->env_ipc_dstva, perm);

		struct PageInfo *pp = page_lookup(curenv->env_pgdir, srcva, NULL);
		if(pp == NULL) {
			return -E_INVAL;
		}
		res = page_insert(env->env_pgdir, pp, env->env_ipc_dstva, perm);

		if(res == 0)
			env->env_ipc_perm = perm;
		// 到此 我们就映射成功了,或者根本就不需要映射
	}

	env->env_ipc_from = curenv->env_id;
	env->env_ipc_recving = 0;
	env->env_ipc_value = value;

	env->env_status = ENV_RUNNABLE;

	return 0;

	// panic("sys_ipc_try_send not implemented");
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	// 进入接收信息的状态
	if((uint32_t)dstva < UTOP && ((uint32_t)dstva & (PGSIZE - 1)) != 0)
		return -E_INVAL;

	curenv->env_ipc_recving = 1;
	curenv->env_ipc_dstva = dstva;
	curenv->env_status = ENV_NOT_RUNNABLE;

	curenv->env_tf.tf_regs.reg_eax = 0;		// 设置返回值
	sched_yield();	// 启动调度器 调度一个新的进程进入CPU指向
	// 此进程不能够被调度程序调度到了
	// 当收到数据后,发送方将把此进程的status变为RUNNABLE
	// 此后,调度程序可以调度到此进程,调度程序使用env_run来启动此进程,
	// 也就是根据我们的env_tf来觉得启动时的状态
	// 我们的env_tf应该是在上次调用系统调用的时候发生中断设置的
	// 我们把env_tf中的eax的值设置为0,然后进程被调度时,中断将返回,返回值为0

	// panic("sys_ipc_recv not implemented");
	return 0;
}

// Return the current time.
static int
sys_time_msec(void)
{
	// LAB 6: Your code here.
	panic("sys_time_msec not implemented");
}

// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.
	// 这里相当于是系统功能调用的分发器,根据系统调用号调用相应的函数进行处理

	// panic("syscall not implemented");

	switch (syscallno) {
	case SYS_cputs:
		sys_cputs((char *)a1, a2);
		return 0;
	case SYS_cgetc:
		return sys_cgetc();
	case SYS_getenvid:
		return sys_getenvid();
	case SYS_env_destroy:
		sys_env_destroy(a1);
		return 0;
	case SYS_page_alloc:
		return sys_page_alloc(a1, (void *)a2, a3);
	case SYS_page_map:
		return sys_page_map(a1, (void *)a2, a3, (void *)a4, a5);
	case SYS_page_unmap:
		return sys_page_unmap(a1, (void *)a2);
	case SYS_exofork:
		return sys_exofork();
	case SYS_env_set_status:
		return sys_env_set_status(a1, a2);
	case SYS_env_set_trapframe:
		return sys_env_set_trapframe(a1, (struct Trapframe *)a2);
	case SYS_env_set_pgfault_upcall:
		return sys_env_set_pgfault_upcall(a1, (void *)a2);
	case SYS_yield:
		sys_yield();
		return 0;
	case SYS_ipc_try_send:
		return sys_ipc_try_send(a1, a2, (void *)a3, a4);
	case SYS_ipc_recv:
		return sys_ipc_recv((void *)a1);
	case NSYSCALLS:
		;
	default:
		return -E_INVAL;
	}
}

