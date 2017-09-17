#include "headers.h"



void UnloadElf(elfbin_t *elf)
{
	if (!elf)
		return;
	munmap(elf->mem, elf->size);
}
int ElfReload(elfbin_t *elf)
{
	char name[256];
	strcpy(name, elf->path);
	UnloadElf(elf);
	load_target(name, elf);
	return 0;
}

int AddSymbol(char *name, Elf64_Addr vaddr, Elf64_Sym *sym, elfbin_t *target)
{
	/* target is target bin with obj code added */
	printf("[+] Add symbol: %s, vaddr 0x%08lx\n", name, vaddr);
	int i, symsiz = sizeof(Elf64_Sym);
	int fd, st_index;
	Elf64_Off symoff;
	uint64_t st_offset, st_start;
	int slen = strlen(name) + 1;
	name[strlen(name)] = '\0';

	char *TargetStbl = &target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];

	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY | O_TRUNC, target->st.st_mode)) == -1)
	{
		perror("open TMP_FILE");
		return -1;
	}


	/* adjust symbol table */
	/* add sizeof sym struct to symtab sh_size */
	sym->st_value = vaddr;
	printf("[+] Sym vaddr: 0x%08lx\n", vaddr);
	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (target->shdr[i].sh_type == SHT_SYMTAB)
		{
			symoff = target->shdr[i].sh_offset + target->shdr[i].sh_size;
			target->shdr[i].sh_size += symsiz;
			while (i++ < target->ehdr->e_shnum) {
				target->shdr[i].sh_offset += symsiz;
				printf("[+] Sym Offset: 0x%08lx\n", target->shdr[i].sh_offset);
			}
		}

	/* get symbol (not DYNSYM) string table info and make any necessary mods to shdrs */
	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (target->shdr[i].sh_type == SHT_STRTAB && i != target->ehdr->e_shstrndx && 
				strcmp(&TargetStbl[target->shdr[i].sh_name], ".dynstr"))
		{
			st_offset = target->shdr[i].sh_offset + target->shdr[i].sh_size - symsiz;
			st_index = i;
			st_start = target->shdr[i].sh_size;

			target->shdr[i].sh_size += slen;
			break;
		}

	/* increase section header offsets after strtab shdr to account for new string */
	for (i = 0; i < target->ehdr->e_shnum; i++)
	{
		/* handle shstrndx having earlier index */
		/* add symsiz to offset */
		if (i == target->ehdr->e_shstrndx)
		{
			target->shdr[i].sh_offset += (symsiz + slen);
			target->shdr[i].sh_addr += (symsiz + slen);
		}

			
		if (i > st_index)
		{
			target->shdr[i].sh_offset += slen;
			target->shdr[i].sh_addr += slen;
		}
	}
	/* adjust p_shoff to accomidate new shdr offset */
	target->ehdr->e_shoff += (symsiz + slen);
	/* point symbol st_name to new string */
	sym->st_name = st_start;

	/*write first chunk up until end of symbol table */
	if (write(fd, target->mem, symoff) != symoff)
	{
		perror("write TMP_FILE symoff");
		return -1;
	}

	if (write(fd, sym, symsiz) != symsiz)
	{
		perror("write TMP_FILE symsiz");
		return -1;
	}
	
	if (write(fd, (target->mem + symoff), st_offset - symoff) != st_offset - symoff)
	{
		perror("write TMP_FILE mem + symoff");
		return -1;
	}

	/* write new string at end of string table */
	if (write(fd, name, slen) != slen)
	{
		perror("write TMP_FILE name");
		return -1;
	}
	//printf("last chunk: %d\n", target->size - st_offset);

	if (write(fd, (target->mem + st_offset), target->size - st_offset) != target->size - st_offset)
	{
		perror("write TMP_FILE final chunk");
		return -1;
	}

	if ((fsync(fd)) == -1)
	{
		perror("fsync(): ");
		return -1;
	}
	/* have to rename for mmap to load right */
	if (rename(TMP_FILE, TMP) < 0)
	{
		perror("rename TMP_FILE, TMP");
		return -1;
	}
	close(fd);

	/*size must be adjusted if multiple calls to AddSym() */
	target->size += symsiz;
	target->size += slen;

	printf("[+] Write sym ok.\n");
	return 1;
}

Elf64_Addr GetRelocSymAddr(char *name, Elf64_Shdr *shdr, int c, uint8_t *objmem)
{
	Elf64_Sym *symtab;
	Elf64_Shdr *shdrp;
	char *SymStrTable;
	int i, j;

	for (shdrp = shdr, i = 0; i < c; i++, shdrp++)
		if (shdrp->sh_type == SHT_SYMTAB)
		{
			SymStrTable = &objmem[shdr[shdrp->sh_link].sh_offset];
			symtab = (Elf64_Sym *)&objmem[shdrp->sh_offset];

			for (j = 0; j < shdrp->sh_size / sizeof(Elf64_Sym); j++, symtab++ )
			{
				//printf("found symname: %s\n", &SymStrTable[symtab->st_name]);
				if(strcmp(&SymStrTable[symtab->st_name], name) == 0) {
				//	printf("match %s\n", name);
					return ((Elf64_Addr)shdr[symtab->st_shndx].sh_addr + symtab->st_value);
				}
			}
		}
	return 0;
}

Elf64_Sym *GetSymByName(char *name, Elf64_Shdr *shdr, int c, uint8_t *objmem)
{
	Elf64_Sym *symtab;
	Elf64_Shdr *shdrp;
	char *SymStrTable;
	int i, j;

	for (shdrp = shdr, i = 0; i < c; i++, shdrp++ )
		if (shdrp->sh_type == SHT_SYMTAB)
		{
			SymStrTable = &objmem[shdr[shdrp->sh_link].sh_offset];
			symtab = (Elf64_Sym *)&objmem[shdrp->sh_offset];

			for (j = 0; j < shdrp->sh_size / sizeof(Elf64_Sym); j++, symtab++)
			{
				if (strcmp(&SymStrTable[symtab->st_name], name) == 0)
				{
					printf("[+] Found symtab: %s addr: 0x%08lx\n", name, symtab);
					return symtab;
				}
			}
		}
	return NULL;
}
