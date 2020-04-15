// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	// 这个函数是fork函数发生page fault时的处理函数
	// 这个处理函数只处理由于内存页为copy-on-write状态的页发生写操作时引起的异常
	// 对于这个异常,我们需要为该内存页生成一个此进程可写的新的内存页
	// 首先我们要检查page fault异常是否是由于 写 copy-on-write 内存所导致的
	extern volatile pde_t uvpt[];
	pte_t pte = uvpt[(uint32_t)addr >> 12];

	if((err & FEC_WR) != FEC_WR || !(pte & PTE_COW))
		panic("pgfault: not write access or no copy-on-write page\n");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.
	// 接下来我们对异常进行处理
	// 我们首先从页表中获取异常发生处的页的权限信息perm
	// perm中肯定是包含PTE_COW的,我们将该位清零,然后田间PTE_W位
	// 另外,由于系统调用对传入的perm有一定的限制,我们需要将perm中的accessed、dirty位清零
	// 然后我们申请新的页,使用UTEMP作为缓冲,将数据拷贝到新的页中,然后将新页映射到原来的虚地址处

	// 这里我们写一下关于读取页表内容的方法
	// 在内存中,有一段4M的内存空间,可以映射整个页表的内容,该位置包含1024块
	// 我们知道,一级页表包含1024个指针,指向1024个二级页表,这里我们使用其中一个特定的指针指向其自身
	// 那么正好就可以用这1024块来保存一个一级页表和1023个二级页表.
	// jos中,一级页表保存的位置被设置为(0x3BD << 22) | (0x3BD << 12),也就是PDX和PTX的值均为0x3BD
	// 我们用(X Y Z)来表示一个地址(X 和 Y 为10位, Z为12位),那么在上述结构中,我们可以通过地址变换来访问页表中的页表项的信息
	// 我们的寻址方式为 首先找到一级页表中偏移量为X的位置,从而找到其指向的二级页表,然后通过二级页表中偏移量为Y的位置,找到内存块
	// 的位置,该内存块中偏移量为Z处的字节即为我们要访问的字节.(显然,我们的页表是以4字节为单位进行访问的,而内存块是按1字节为单位
	// 进行访问的,因此,Z为12位而X和Y为10位).
	// 我们知道X为0x3BD时,通过一级页表访问到的二级页表实际上就是一级页表本身,那么我们就可以通过(0x3BD X Y 00)来访问(X Y Z)
	// 对应的二级页表的页表项的内容(由于这里的4k字节对应同一个页表项,所以其内容自然是与Z无关的,而这里我们也没有用到Z)
	// 同样,我们也可以访问一级页表的值,通过访问(0x3BD 0x3BD X 00),我们第一次访问的二级页表实际上就是一级页表,第二次访问的内存块
	// 也是一级页表,那么该位置就是(X Y Z)地址在一级页表中对应的那么页表项.

	// 注意:在这个处理过程中可能会用到当前进程的进程号
	// 在fork的过程中,当子进程第一次启动时,它的代码段的内存空间的权限就包含copy-on-write
	// 而此时,子进程还没有更新其thisenv全局变量的值,因此我们需要使用系统调用sys_getenvid来获取envid使用
	// 而不能够直接使用thisenv->env_id作为当前进程的id号
	envid_t envid = sys_getenvid();

	int perm = pte & 0xfff;
	perm = perm & ~(PTE_COW);
	perm = perm | PTE_W;
	perm &= PTE_SYSCALL;
	int res = sys_page_alloc(envid, (void *)UTEMP, perm);
	if(res != 0)
		panic("sys_page_alloc: %e\n", res);
	memmove((void *)UTEMP, (void *)ROUNDDOWN(addr, PGSIZE), PGSIZE);
	res = sys_page_map(envid, (void *)UTEMP, envid, (void *)ROUNDDOWN(addr, PGSIZE), perm);
	if(res != 0)
		panic("sys_page_map: %e\n", res);
	res = sys_page_unmap(envid, (void *)UTEMP);
	if(res != 0)
		panic("sys_page_unmap: %e\n", res);

	// panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	// 这里我们把当前运行的进程的页号为pn的页映射到envid进程相同虚地址的位置,使用copy-on-write意义上的拷贝
	// 如果页的权限(保存在其对应的二级页表中)包括PTE_W或者PTE_COW,那么我们需要将该页的权限中的可写清除并添加PTE_COW
	// 注意到这里我们不能够直接修改本进程的页表中页表项的权限内容,因此我们可以将映射到envid进程的页再映射回本进程中
	// 如果是只读的话,就仍然是只读权限
	// 注意实际页表中的权限位可能包含accessed和dirty位,在作为参数传递给系统调用时,需要将这些无效位清除
	// 对于权限位是PTE_SHARE的内存块,我们直接使用原来的权限信息(当然要使用PTE_SYSCALL进行筛选),将该块映射到新的进程中
	// 新进程和原进程直接共享这个内存块
	int perm;
	int ptePerm;
	extern volatile pte_t uvpt[];
	pte_t pte = uvpt[(PDX(pn << 12) << 10) + PTX(pn << 12)];
	ptePerm = pte & PTE_SYSCALL;
	perm = ptePerm;
	if(ptePerm & PTE_SHARE) {
		perm = perm;
	} else if(ptePerm & PTE_W || ptePerm & PTE_COW) {
		perm &= ~(PTE_W);
		perm |= PTE_COW;
		// 该页是write或者copy-on-write的
	} else {
		perm = ptePerm;	// 该页不能write,也不是copy-on-write的
	}
	int res = sys_page_map(thisenv->env_id, (void *)(pn * PGSIZE), envid, (void *)(pn * PGSIZE), perm);
	if(res != 0)
		panic("sys_page_map: %e\n", res);

	if(perm & PTE_COW) {
		res = sys_page_map(envid, (void *)(pn * PGSIZE), thisenv->env_id, (void *)(pn * PGSIZE), perm);
		if(res != 0)
			panic("sys_page_map: %e\n", res);
	}

	// panic("duppage not implemented");
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	// 这里就是fork函数的实现了
	set_pgfault_handler(pgfault);

	envid_t new_env_id = sys_exofork();
	if(new_env_id < 0) {
		panic("sys_exofork: %e", new_env_id);
	} else if(new_env_id == 0) {
		// 这里是子进程开始执行的位置 需要修改其thisenv的值,创建进程的时候,该值是从父进程处拷贝过来的
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	uint8_t *addr;
	// 我们还是对整个内存空间进行扫描,来找到当前进程拥有的所有的内存块
	// 我们遍历整个页表就可以实现这个功能
	// 由于很多情况下一级页表的内容就为空了,这是不需要遍历二级页表,所以其实应该不会花上太多的时间
	// 这里只遍历到USTACKTOP的位置,再往上就是异常栈空间和内核空间了
	// 这里我们就已经把正常栈的空间给映射到了新的进程中
	for(addr = (uint8_t *)UTEXT; addr < (uint8_t *)USTACKTOP;) {
		extern volatile pte_t uvpd[];
		extern volatile pte_t uvpt[];
		if(uvpd[PDX(addr)] == 0) {
			addr += PTSIZE;
			continue;
		}
		if(uvpt[(PDX(addr) << 10) + PTX(addr)] == 0) {
			addr += PGSIZE;
			continue;
		}
		duppage(new_env_id, (uint32_t)addr >> PGSHIFT);
		addr += PGSIZE;
	}

	// 然后我们需要为其分配一个异常栈
	// 然后为子进程设置异常处理函数
	int res = sys_page_alloc(new_env_id, (void *)(UXSTACKTOP - PGSIZE), PTE_U | PTE_P | PTE_W);
	if(res != 0)
		panic("sys_page_alloc: %e\n", res);
	extern void _pgfault_upcall(void);
	res = sys_env_set_pgfault_upcall(new_env_id, _pgfault_upcall);
	if(res != 0)
		panic("sys_env_set_pgfault_upcall: %e\n", res);

	// 将子进程的状态设置为可运行状态,这样调度程序就可以调度子进程来运行了
	if ((res = sys_env_set_status(new_env_id, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", res);
	
	return new_env_id;

	// panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
