#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < ARRAY_SIZE(excnames))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];
	// LAB 3: Your code here.
	// 设置中断描述符表 idt
	// SETGATE有5个参数,第一个为中断描述符表的表项
	// 第二个是一个标志位,用来表明是trap还是Interrupt,二者的区别好像在于是否运行中断嵌套,不是很清楚
	// 第三个和第四个参数为 中断发生时,处理器跳转位置的CS和EIP,CS应该设置为GD_KT(这是内核的代码段的CS)
	// EIP设置为入口地址,入口在trapentry.S中定义,我们用extern引用它们,这样的话函数名就是相应的入口地址
	// 第五个参数 特权级,特权级的意思是,如果要使用int xx来产生中断信号的话,那么使用该特权级来触发中断
	// 也就是说,这个时候中断是从设置的特权级被触发的,那么要求是我们只能用int来调用一部分特权级比当前执行的程序
	// 更低的中断,而特权级被设置为0的中断,我们在用户态(特权级为3)时是不能用int来触发的
	// 那么对应硬件中断而言,这个特权级对中断源就不会有什么限制,但是中断处理中应该是将这个值作为中断源的特权级
	// 这个特权级要怎么设置,其实还是不是很清楚,可能在intel的手册里面有吧,但是intel的指令集的手册是在是太长了...
	extern void divide_trap(void);
	SETGATE(idt[0], 0, GD_KT, divide_trap, 0);

	extern void debug_trap(void);
	SETGATE(idt[1], 0, GD_KT, debug_trap, 0);
	
	extern void nmi_trap(void);
	SETGATE(idt[2], 0, GD_KT, nmi_trap, 0);

	extern void breakpoint_trap(void);
	SETGATE(idt[3], 1, GD_KT, breakpoint_trap, 3);

	extern void overflow_trap(void);
	SETGATE(idt[4], 1, GD_KT, overflow_trap, 0);

	extern void bound_trap(void);
	SETGATE(idt[5], 0, GD_KT, bound_trap, 0);

	extern void illegal_trap(void);
	SETGATE(idt[6], 0, GD_KT, illegal_trap, 0);

	extern void device_trap(void);
	SETGATE(idt[7], 0, GD_KT, device_trap, 0);

	extern void double_fault_trap(void);
	SETGATE(idt[8], 0, GD_KT, double_fault_trap, 0);

	extern void task_switch_trap(void);
	SETGATE(idt[10], 0, GD_KT, task_switch_trap, 0);

	extern void seg_trap(void);
	SETGATE(idt[11], 0, GD_KT, seg_trap, 0);

	extern void stack_trap(void);
	SETGATE(idt[12], 0, GD_KT, stack_trap, 0);

	extern void gp_trap(void);
	SETGATE(idt[13], 0, GD_KT, gp_trap, 0);

	extern void page_fault_trap(void);
	SETGATE(idt[14], 0, GD_KT, page_fault_trap, 0);

	extern void fp_error_trap(void);
	SETGATE(idt[16], 0, GD_KT, fp_error_trap, 0);

	extern void align_trap(void);
	SETGATE(idt[17], 0, GD_KT, align_trap, 0);

	extern void machine_trap(void);
	SETGATE(idt[18], 0, GD_KT, machine_trap, 0);

	extern void simd_trap(void);
	SETGATE(idt[19], 0, GD_KT, simd_trap, 0);

	extern void syscall_trap(void);
	SETGATE(idt[48], 0, GD_KT, syscall_trap, 3);
	// 这里的特权级需要设置为3
	
	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//   - Initialize cpu_ts.ts_iomb to prevent unauthorized environments
	//     from doing IO (0 is not the correct value!)
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:
	// 为每个CPU初始化他们各自的TSS和IDT
	// IDT的设置其实是一样的,都是上面trip_init函数中写的那样
	// TSS的设置和单处理器时有所不同(其实单处理器时的状态就是cpu_id为0时的设置方法)
	// TSS应该是GDT中的一些项,每个CPU的TSS都对应与GDT中的一个项,这个项的位置开始与GD_TSS0>>3的位置,
	// 当然右移3位的目的应该是在设置一些寄存器的时候方便起见,当然,这可能也限制了我们系统能够支持的CPU的数量吧
	// 应该最多只能够支持8个CPU

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - (KSTKSIZE + KSTKGAP) * thiscpu->cpu_id;
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	thiscpu->cpu_ts.ts_iomb = sizeof(struct Taskstate);
	// ts.ts_esp0 = KSTACKTOP;
	// ts.ts_ss0 = GD_KD;
	// ts.ts_iomb = sizeof(struct Taskstate);

	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id] = SEG16(STS_T32A, (uint32_t) (&(thiscpu->cpu_ts)), sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id].sd_s = 0;
	// gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
	// 				sizeof(struct Taskstate) - 1, 0);
	// gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0 + (thiscpu->cpu_id << 3));

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	// 这里应该是要根据tf中的内容判断中断的类型,然后作出相应的处理
	// 我们在这先直接打印相关的信息然后终止该进程
	// 后续在根据需求添加具体的处理程序
	// 这里添加了对几个中断的特殊处理
	// 页错误、断点中断、系统调用
	if(tf->tf_trapno == T_PGFLT)
		page_fault_handler(tf);
	else if(tf->tf_trapno == T_BRKPT)
		monitor(tf);
	else if(tf->tf_trapno == T_SYSCALL) {
		tf->tf_regs.reg_eax = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx, tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx, tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
		return;
	}

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		// 上锁
		assert(curenv);
		lock_kernel();

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	// 如果是内核态发生page faults,那么直接panic
	if((tf->tf_cs & 3) != 3) {
		panic("kernel-mode page faults\n");
	}

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// It is convenient for our code which returns from a page fault
	// (lib/pfentry.S) to have one word of scratch space at the top of the
	// trap-time stack; it allows us to more easily restore the eip/esp. In
	// the non-recursive case, we don't have to worry about this because
	// the top of the regular user stack is free.  In the recursive case,
	// this means we have to leave an extra word between the current top of
	// the exception stack and the new stack frame because the exception
	// stack _is_ the trap-time stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
	// 这里需要构建正确的栈结构来实现程序的跳转.
	// 我们将需要压入异常栈的数据使用异常栈的指针送入到异常栈中
	// 然后我们使用env_run函数实现程序的跳转
	// 在跳转的过程中,我们需要实现栈的切换(即修改esp)和程序地址的切换(即修改eip)
	// 因此我们需要把正确的esp和eip值设置到该进程信息块的tf字段中(该字段保存了进程下次启动时的各个寄存器的值)
	uintptr_t esp = UXSTACKTOP;
	if(curenv->env_pgfault_upcall != NULL) {
		// 表示 该进程存在page fault的处理程序
		// 如果没有分配异常堆栈 或者异常堆栈不能访问 那么就杀死这个进程
		user_mem_assert(curenv, (void *)(UXSTACKTOP - 4), PGSIZE, PTE_P);
		if(tf->tf_esp < UXSTACKTOP && tf->tf_esp >= (UXSTACKTOP - PGSIZE)) {
			// 说明 我们是在异常处理时出现page fault,然后到这里来的
			// 这种情况下,我们需要检查在向异常堆栈中写入数据的时候是否会溢出
			user_mem_assert(curenv, (void *)(tf->tf_esp - 56), 56, PTE_P);
			esp = tf->tf_esp - 4;	// 空出32bit的部分
			*(int *)esp = 0;
		}
		esp -= 4;
		*(int *)esp = tf->tf_esp;
		esp -= 4;
		*(int *)esp = tf->tf_eflags;
		esp -= 4;
		*(int *)esp = tf->tf_eip;
		esp -= 4;
		*(int *)esp = tf->tf_regs.reg_eax;
		esp -= 4;
		*(int *)esp = tf->tf_regs.reg_ecx;
		esp -= 4;
		*(int *)esp = tf->tf_regs.reg_edx;
		esp -= 4;
		*(int *)esp = tf->tf_regs.reg_ebx;
		esp -= 4;
		*(int *)esp = tf->tf_regs.reg_oesp;
		esp -= 4;
		*(int *)esp = tf->tf_regs.reg_ebp;
		esp -= 4;
		*(int *)esp = tf->tf_regs.reg_esi;
		esp -= 4;
		*(int *)esp = tf->tf_regs.reg_edi;
		esp -= 4;
		*(int *)esp = tf->tf_err;
		esp -= 4;
		*(int *)esp = fault_va;
		// 上面完成了异常堆栈数据的填入 下面我们修改env的tf字段中断相关寄存器 实现跳转
		tf->tf_eip = (uintptr_t)curenv->env_pgfault_upcall;
		tf->tf_esp = esp;

		// 使用env_run来实现跳转 env_run会根据我们上面设置的tf_eip和tf_esp来实现程序流程的跳转和堆栈的切换
		env_run(curenv);
	}

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

