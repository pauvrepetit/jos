#include <inc/mmu.h>
#include <inc/memlayout.h>

// Page fault upcall entrypoint.

// This is where we ask the kernel to redirect us to whenever we cause
// a page fault in user space (see the call to sys_set_pgfault_handler
// in pgfault.c).
//
// When a page fault actually occurs, the kernel switches our ESP to
// point to the user exception stack if we're not already on the user
// exception stack, and then it pushes a UTrapframe onto our user
// exception stack:
//
//	trap-time esp
//	trap-time eflags
//	trap-time eip
//	utf_regs.reg_eax
//	...
//	utf_regs.reg_esi
//	utf_regs.reg_edi
//	utf_err (error code)
//	utf_fault_va            <-- %esp
//
// If this is a recursive fault, the kernel will reserve for us a
// blank word above the trap-time esp for scratch work when we unwind
// the recursive call.
//
// We then have call up to the appropriate page fault handler in C
// code, pointed to by the global variable '_pgfault_handler'.

.text
.globl _pgfault_upcall
_pgfault_upcall:
	// Call the C page fault handler.
	// 这里是调用page fault处理函数的位置 首先将参数压栈,然后调用该函数
	pushl %esp			// function argument: pointer to UTF
	movl _pgfault_handler, %eax
	call *%eax
	addl $4, %esp			// pop function argument
	// 到这里 page fault处理结束了 并且恢复到了原来的栈结构
	
	// Now the C page fault handler has returned and you must return
	// to the trap time state.
	// Push trap-time %eip onto the trap-time stack.
	//
	// Explanation:
	//   We must prepare the trap-time stack for our eventual return to
	//   re-execute the instruction that faulted.
	//   Unfortunately, we can't return directly from the exception stack:
	//   We can't call 'jmp', since that requires that we load the address
	//   into a register, and all registers must have their trap-time
	//   values after the return.
	//   We can't call 'ret' from the exception stack either, since if we
	//   did, %esp would have the wrong value.
	//   So instead, we push the trap-time %eip onto the *trap-time* stack!
	//   Below we'll switch to that stack and call 'ret', which will
	//   restore %eip to its pre-fault value.
	//
	//   In the case of a recursive fault on the exception stack,
	//   note that the word we're pushing now will fit in the
	//   blank word that the kernel reserved for us.
	//
	// Throughout the remaining code, think carefully about what
	// registers are available for intermediate calculations.  You
	// may find that you have to rearrange your code in non-obvious
	// ways as registers become unavailable as scratch space.
	//
	// LAB 4: Your code here.

	// 下面是从page fault的处理过程中返回的方法
	// 该过程需要正确的完成esp和eip的变化
	// 对于单级的处理,我们的异常栈中只包含这次异常处理前压入的数据
	// 我们首先从中读取出最上面的trap-time esp的值,该值为需要返回的位置的当前栈顶
	// 然后我们读出trap-time eip的值,该值为返回时需要使用的eip值
	// 通过上面读到的esp的值,将trap-time eip压入上次的栈中 并将当前栈最上面的那个trap-time esp的值自增4
	// 另外,为了避免出现错误,我们完成上述操作后,将栈中的trap-time eip位置的值赋值为trap-time eflags位置的值
	// (后面我们将看到为什么要这样做)
	// 接下来我们就可以开始恢复寄存器了
	// 首先将栈顶esp加8,相当于让utf_fault_va和utf_err出栈
	// 然后使用popal恢复八个通用寄存器
	// 接下来栈顶位置的值为trap-time eip,由于我们在上面将该位置的值赋值为了trap-time eflags的值,因此我们可以直接
	// 使用popf来将该数据出栈(当然,好像可以直接用加4的方法出栈(写的时候有点想多了)),然后再使用popf来将真正的trap-time eflags出栈
	// 到此栈中只剩下一个trap-time esp的值,我们将该值出栈到esp寄存器中,就完成了栈的切换
	// 当然,由于我们在最开始的处理,切换后的栈中,栈顶位置即为我们最后返回时需要的eip的值
	// 此时,使用ret将eip出栈到eip寄存器中,即完成了程序执行路径的切换

	// 当然,对于多级的page fault处理而言,上面的操作其实是一样的
	// 就是,此时我们的栈的最上面的trap-time esp实际上就指向了其上面空出4个字节后的位置
	// 我们进行上面的操作,就正好将返回的eip的值存入了我们在栈中预留下来的4个字节的位置(这就是预留那4个字节的意义)

	movl 48(%esp), %eax
	movl 40(%esp), %ebx
	movl %ebx, -4(%eax)
	addl $-4, %eax
	mov %eax, 48(%esp)
	movl 44(%esp), %eax
	movl %eax, 40(%esp)

	// Restore the trap-time registers.  After you do this, you
	// can no longer modify any general-purpose registers.
	// LAB 4: Your code here.

	add $8, %esp
	popal

	// Restore eflags from the stack.  After you do this, you can
	// no longer use arithmetic operations or anything else that
	// modifies eflags.
	// LAB 4: Your code here.

	popf
	popf

	// Switch back to the adjusted trap-time stack.
	// LAB 4: Your code here.

	pop %esp

	// Return to re-execute the instruction that faulted.
	// LAB 4: Your code here.

	ret
