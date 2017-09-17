/* TEST program to relocate object file into elf binary */
/* copile with make 
 * depends: utils.c inject.c
 */

/* Code taken from quenya32bit and skeksi_virus by Elfmaster
 *
 * https://github.com/elfmaster/skeksi_virus/blob/master/virus.c
 * http://bitlackeys.org/projects/quenya_32bit.tgz
 * 
 * go buy his book: Learning Linux Binary Analysis
 */

#include "headers.h"

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
	elf->mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
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



int relocate(elfbin_t *target, elfbin_t *relf, char *objname) 
{
	Elf64_Sym *symtab, *symbol;
	Elf64_Shdr *TargetSection;
	/* update to 32bit for R_X86_64_PC32 */
	Elf32_Addr TargetAddr; 
	Elf32_Addr *RelocPtr;
	Elf32_Addr RelVal;
	int TargetIndex;
	//char *symName;
	//char *targname;
	int i, symstrndx, j;
	Elf64_Addr objvaddr;
	elfbin_t dst;
	Elf64_Rela *rela;
	int link;


	elfbin_t obj;
	char *SymStringTable;

	/* total length of object code */
	uint32_t totLen, secLen;
	uint8_t *ObjCode;

	/* Load the ET_REL file into memory as 'obj' */
	
	printf("[+] loading object %s\n", objname);
	if(load_target(objname, &obj) == -1) {
		perror("Unable to load ELF object\n");
		return -1;
	}


	/* allocate memory for object code */
	for (i = 0, totLen = 0; i < obj.ehdr->e_shnum; i++ )
		if (obj.shdr[i].sh_type == SHT_PROGBITS)
			totLen += obj.shdr[i].sh_size;

	if ((ObjCode = (uint8_t *)malloc(totLen)) == NULL)
	{
		perror("malloc error:");
		return -1;
	}

	/* address to inject object code in target */
	/* objvaddress is target bin */
	objvaddr = target->phdr[TEXT].p_vaddr + target->phdr[TEXT].p_memsz;

	/* adjust section addresses */
	for (secLen = 0, i = 0;i < obj.ehdr->e_shnum; i++)
	{
		if (obj.shdr[i].sh_type == SHT_PROGBITS)
		{
			obj.shdr[i].sh_addr = objvaddr + secLen;
			secLen += obj.shdr[i].sh_size;
			printf("[+] Adjust Section Addr [%d] 0x%08lx\n", i, obj.shdr[i].sh_addr);
		}
		if (obj.shdr[i].sh_type == SHT_STRTAB && i != obj.ehdr->e_shstrndx)
			symstrndx = i;
	}
	SymStringTable = &obj.mem[obj.shdr[symstrndx].sh_offset];
	
	/* PERFORM RELOCATIONS ON OBJECT CODE */
	for (i = 0; i < obj.ehdr->e_shnum; i++)
	{
		/* I'm leaving out SHT_REL for brevity */
		if (obj.shdr[i].sh_type == SHT_RELA)
		{
			/* small bug in quenya32 */
			/* rela statement needs to be before for loop */
			rela = (Elf64_Rela *)(obj.mem + obj.shdr[i].sh_offset);
			for (j = 0; j < obj.shdr[i].sh_size / sizeof(Elf64_Rela); j++, rela++)
			{
		// move this		rela = (Elf64_Rela *)(obj.mem + obj.shdr[i].sh_offset);
				link = obj.shdr[i].sh_link;
				/* symbol table */

				// address at link address = symtab pointer
				symtab = (Elf64_Sym *)&obj.mem[obj.shdr[link].sh_offset];
				//symtab = (Elf64_Sym *)obj.section[obj.shdr[i].sh_link];
				
				/* symbol index from r_info */
				symbol = &symtab[ELF64_R_SYM(rela->r_info)];
				/*TODO add write symbol function from elf_mmap.c */
				/* or use section = &obj.mem[obj.shdr[section].sh_offset] */

				/* section to modify */
				TargetSection = &obj.shdr[obj.shdr[i].sh_info];
				TargetIndex = obj.shdr[i].sh_info;
				//printf("[+] Target Section: 0x%08x\n", TargetSection);
				//printf("[+] Target Index: 0x%08x\n", TargetIndex);


				/* Target location */
				TargetAddr = TargetSection->sh_addr + rela->r_offset;
				printf("[+] Target Addr: 0x%08x\n", TargetAddr);

				/* Pointer to relocation target */
				RelocPtr = (Elf32_Addr *)(&obj.mem[obj.shdr[TargetIndex].sh_offset] + rela->r_offset);

				/* relocation value */
				RelVal = symbol->st_value;
				RelVal += obj.shdr[symbol->st_shndx].sh_addr;

				printf("[+] RelVal 0x%08x\n", RelVal);
				switch (ELF64_R_TYPE(rela->r_info))
				{
				/* R_386_PC32	2	word32 S + A - P */

				case R_X86_64_PC32:
					*RelocPtr += RelVal;
					*RelocPtr += rela->r_addend;
					*RelocPtr -= TargetAddr;
					printf("[+] Reloc ptr (R_X86_64_PC32) 0x%08x\n", *RelocPtr);
					break;

				/* R_386_32	1	word32 S + A */
				case R_X86_64_32:
					*RelocPtr += RelVal;
					*RelocPtr += rela->r_addend;
					printf("[+] Reloc ptr (R_X86_64) 0x%08x\n", *RelocPtr);
					break;
				}
				printf("[+] Section Header Reloc 0x%08x %s addr: 0x%x\n", RelVal, &SymStringTable[symbol->st_name], TargetAddr);
			}
		}
	}

	for (secLen = 0, i = 0; i < obj.ehdr->e_shnum; i++)
		if (obj.shdr[i].sh_type == SHT_PROGBITS)
		{
			memcpy(&ObjCode[secLen], &obj.mem[obj.shdr[i].sh_offset], obj.shdr[i].sh_size);
			printf("[+] memcpy to Objcode %lu bytes\n", obj.shdr[i].sh_size);
			secLen += obj.shdr[i].sh_size;
		}

	/* Inject Relocated Object */
	if ((objvaddr = inject_elf(target, ObjCode, totLen)) == -1)
		return -1;

	printf("[+] Injected code at = 0x%08lx\n", objvaddr);
	/* load elf with object code in it */

	if (load_target(TMP, &dst) == -1)
	{
		printf("Could not load target %s\n", TMP);
		return -1;
	}

	for (i = 0; i < obj.ehdr->e_shnum; i++)
		if (obj.shdr[i].sh_type == SHT_SYMTAB)
		{
			link = obj.shdr[i].sh_link;
			/* according to the elf spec sh_link for SHT_SYMTAB */
			/* is The section header index of the associated string table */
			SymStringTable = (char *)&obj.mem[obj.shdr[link].sh_offset];
			symtab = (Elf64_Sym *)&obj.mem[obj.shdr[i].sh_offset];

			for (j = 0; j < obj.shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++)
				if ((ELF64_ST_TYPE(symtab->st_info) == STT_FUNC) || 
						(ELF64_ST_TYPE(symtab->st_info) == STT_OBJECT))
				{
					AddSymbol(
							&SymStringTable[symtab->st_name],
							GetRelocSymAddr(&SymStringTable[symtab->st_name], obj.shdr, obj.ehdr->e_shnum, obj.mem),
							GetSymByName(&SymStringTable[symtab->st_name], obj.shdr, obj.ehdr->e_shnum, obj.mem),
							&dst);
					UnloadElf(&dst);
					if (load_target(TMP, &dst) == -1)
					{
						printf("[-] could not load TMP_FILE\n");
						return -1;
					}
						
				}
		}

	UnloadElf(&obj);

	relf = &dst;

	return 0;

}

int main(int argc, char **argv) {
	elfbin_t e = {0};
	elfbin_t *elf = &e;
	elfbin_t *dst;
	if (argc < 3)
	{
		printf("usage: %s target obj\n", argv[0]);
		return -1;
	}

	int result = load_target(argv[1], elf);
	if (result < 0) {
		printf("error load_target.\n");
		perror("load target");
		return -1;
	}


	if (relocate(elf, dst, argv[2]) == -1)
	{
		perror("error relocate:");
		return -1;
	}
	UnloadElf(dst);
	UnloadElf(elf);
	printf("success!\n");


	return 0;
}

