
long _write (long fd, void *buf, unsigned long len)
{
	long ret;

	__asm__ volatile(
			"push %%rbx\n"
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $1, %%rax\n"
			"syscall\n": : "g"(fd), "g"(buf), "g"(len)); 
	asm("mov %%rax, %0\n"
		       "pop %%rbx" : "=r"(ret));
	return ret;
}

int evil_puts(void)
{
	_write(1, "HAHA puts() has been hijacked!\n", 31);
}

