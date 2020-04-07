// Called from entry.S to get us going.
// entry.S already took care of defining envs, pages, uvpd, and uvpt.

#include <inc/lib.h>

extern void umain(int argc, char **argv);

const volatile struct Env *thisenv;
const char *binaryname = "<unknown>";

void
libmain(int argc, char **argv)
{
	// set thisenv to point at our Env structure in envs[].
	// LAB 3: Your code here.
	// 使用系统功能调用获取到当前进程的id,然后从进程列表中逐个的比较id,找到id相等的那个进程信息块,保存该位置的指针
	envid_t envid = sys_getenvid();
	int i = 0;
	for(; i < NENV; i++) {
		if(envs[i].env_id == envid) {
			thisenv = &envs[i];
			break;
		}
	}

	// save the name of the program so that panic() can use it
	if (argc > 0)
		binaryname = argv[0];

	// call user main routine
	umain(argc, argv);

	// exit gracefully
	exit();
}

