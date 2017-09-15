/* includes itc for lelf2 */
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

#define NO_JMP_CODE ~0L
#define PAGE_SIZE 4096
#define TMP ".zyx.tmp.bin"
#define TMP_FILE ".elfmod-bin"
#define TEXT 2
#define PAGE_SIZE 4096

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

struct linkng_info
{
	char name[256];
	int index;
	int count;
	uint64_t r_offset;
	uint64_t r_info;
	uint64_t s_value;
	int r_type;
};


/* shared functions */
void UnloadElf(elfbin_t *elf);
int ElfReload(elfbin_t *elf);
int AddSymbol(char *name, Elf64_Addr vaddr, Elf64_Sym *sym, elfbin_t *target);

Elf64_Addr GetRelocSymAddr(char *name, Elf64_Shdr *shdr, int c, uint8_t *objmem);
Elf64_Sym *GetSymByName(char *name, Elf64_Shdr *shdr, int c, uint8_t *objmem);
int load_target(const char *path, elfbin_t *elf);
int inject_elf(elfbin_t *target, uint8_t *parasite, int parasite_size);
