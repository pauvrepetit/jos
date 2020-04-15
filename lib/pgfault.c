// User-level page fault handler support.
// Rather than register the C page fault handler directly with the
// kernel as the page fault handler, we register the assembly language
// wrapper in pfentry.S, which in turns calls the registered C
// function.

#include <inc/lib.h>


// Assembly language pgfault entrypoint defined in lib/pfentry.S.
extern void _pgfault_upcall(void);

// Pointer to currently installed C-language pgfault handler.
void (*_pgfault_handler)(struct UTrapframe *utf);

//
// Set the page fault handler function.
// If there isn't one yet, _pgfault_handler will be 0.
// The first time we register a handler, we need to
// allocate an exception stack (one page of memory with its top
// at UXSTACKTOP), and tell the kernel to call the assembly-language
// _pgfault_upcall routine when a page fault occurs.
//
void
set_pgfault_handler(void (*handler)(struct UTrapframe *utf))
{
	int r;

	if (_pgfault_handler == 0) {
		// First time through!
		// LAB 4: Your code here.
		// 这里就是为当前进程设置page fault的处理程序
		// 如果是第一次调用的话,我们要为进程分配一个异常栈
		sys_page_alloc(thisenv->env_id, (void *)(UXSTACKTOP - PGSIZE), PTE_U | PTE_P | PTE_W);
		// 这里我们使用系统调用为进程设置异常处理程序的入口地址
		// 注意到这里不能够设置为handler,当然,也不能够拿到if的外面设置为handler
		// 由于handler函数需要传递参数,因此我们使用汇编代码来为其完成参数传递需要的压栈操作
		// 将异常处理程序的入口设置为汇编代码的入口,才能够实现其正常的功能
		// 这样也有一定的好处,我们如果要切换异常处理程序的话,只需要修改汇编中的参数_pgfault_handler的值而不需要修改进程信息块中的数据(好像也不是很大的好处啊...)
		sys_env_set_pgfault_upcall(thisenv->env_id, _pgfault_upcall);
		// panic("set_pgfault_handler not implemented");
	}

	// Save handler pointer for assembly to call.
	_pgfault_handler = handler;
}
