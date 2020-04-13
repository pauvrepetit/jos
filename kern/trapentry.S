/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 * 为中断添加入口,这里是直接调用的上面的两个宏
 */

TRAPHANDLER_NOEC(divide_trap, T_DIVIDE)
TRAPHANDLER_NOEC(debug_trap, T_DEBUG)
TRAPHANDLER_NOEC(nmi_trap, T_NMI)
TRAPHANDLER_NOEC(breakpoint_trap, T_BRKPT)
TRAPHANDLER_NOEC(overflow_trap, T_OFLOW)
TRAPHANDLER_NOEC(bound_trap, T_BOUND)
TRAPHANDLER_NOEC(illegal_trap, T_ILLOP)
TRAPHANDLER_NOEC(device_trap, T_DEVICE)
TRAPHANDLER(double_fault_trap, T_DBLFLT)

TRAPHANDLER(task_switch_trap, T_TSS)
TRAPHANDLER(seg_trap, T_SEGNP)
TRAPHANDLER(stack_trap, T_STACK)
TRAPHANDLER(gp_trap, T_GPFLT)
TRAPHANDLER(page_fault_trap, T_PGFLT)

TRAPHANDLER_NOEC(fp_error_trap, T_FPERR)
TRAPHANDLER_NOEC(align_trap, T_ALIGN)
TRAPHANDLER_NOEC(machine_trap, T_MCHK)
TRAPHANDLER_NOEC(simd_trap, T_SIMDERR)

TRAPHANDLER_NOEC(syscall_trap, T_SYSCALL)

TRAPHANDLER_NOEC(irq_trap0, IRQ_OFFSET)
TRAPHANDLER_NOEC(irq_trap1, IRQ_OFFSET + 1)
TRAPHANDLER_NOEC(irq_trap2, IRQ_OFFSET + 2)
TRAPHANDLER_NOEC(irq_trap3, IRQ_OFFSET + 3)
TRAPHANDLER_NOEC(irq_trap4, IRQ_OFFSET + 4)
TRAPHANDLER_NOEC(irq_trap5, IRQ_OFFSET + 5)
TRAPHANDLER_NOEC(irq_trap6, IRQ_OFFSET + 6)
TRAPHANDLER_NOEC(irq_trap7, IRQ_OFFSET + 7)
TRAPHANDLER_NOEC(irq_trap8, IRQ_OFFSET + 8)
TRAPHANDLER_NOEC(irq_trap9, IRQ_OFFSET + 9)
TRAPHANDLER_NOEC(irq_trap10, IRQ_OFFSET + 10)
TRAPHANDLER_NOEC(irq_trap11, IRQ_OFFSET + 11)
TRAPHANDLER_NOEC(irq_trap12, IRQ_OFFSET + 12)
TRAPHANDLER_NOEC(irq_trap13, IRQ_OFFSET + 13)
TRAPHANDLER_NOEC(irq_trap14, IRQ_OFFSET + 14)
TRAPHANDLER_NOEC(irq_trap15, IRQ_OFFSET + 15)

/*
 * Lab 3: Your code here for _alltraps
 * 实现_alltraps,根据进程保存寄存器现场的结构,我们对一些寄存器进行压栈,给ds和es设置为GD_KD(内核的数据段描述符)
 * 调用trap函数对中断进行处理
 * 这里需要修改eflags中的值来关闭对外部中断的响应(对irq的响应)
 */

_alltraps:
	pushl %ds
	pushl %es
	pusha
	pushl $GD_KD
	pushl $GD_KD
	popl %ds
	popl %es
	pushl %eax
	pushl %ebx
	pushf
	popl %eax
	movl $FL_IF, %ebx
	notl %ebx
	andl %ebx, %eax
	pushl %eax
	popf
	popl %ebx
	popl %eax

	push %esp
	call trap
