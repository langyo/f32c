#include <string.h>
#include <unistd.h>

#include <sys/elf32.h>


int
elfinfo(int fd, uint32_t *entry, uint32_t *tsiz, uint32_t *dsiz)
{
	Elf32_Ehdr ehdr;
	Elf32_Shdr shdr;
	int i, len;

	if (lseek(fd, 0, SEEK_SET) != 0)
		return (-1);

	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
		return (-1);

	if (strncmp((void *) ehdr.e_ident, ELFMAG, SELFMAG))
		return (-1);

	if (ehdr.e_version != EV_CURRENT)
		return (-1);

	if (ehdr.e_ehsize != sizeof(ehdr))
		return (-1);

	if (ehdr.e_type != ET_EXEC)
		return (-1);

#ifdef __mips__
	if (ehdr.e_machine != EM_MIPS)
		return (-1);
#endif
#ifdef __riscv
	if (ehdr.e_machine != EM_RISCV)
		return (-1);
#endif

	if (lseek(fd, ehdr.e_shoff, SEEK_SET) != ehdr.e_shoff)
		return (-1);

	/* Compute total text and data segment sizes */
	*entry = ehdr.e_entry;
	*tsiz = *dsiz = 0;
	for (i = 0; i < ehdr.e_shnum; i++) {
		if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr))
			return (-1);
		
		/* Round up allocation to word-aligned size */
		len = (shdr.sh_size + 3) & ~3;
		if ((shdr.sh_flags & SHF_ALLOC) == 0)
			continue;
		if (shdr.sh_type != SHT_PROGBITS && shdr.sh_type != SHT_NOBITS)
			continue;
		if (shdr.sh_flags & SHF_EXECINSTR)
			*tsiz = shdr.sh_addr - *entry + len;
		else
			*dsiz = shdr.sh_addr - *entry - *tsiz + len;
	}

	return (0);
}


int
elfload(int fd, char *tp, uint32_t tsiz, char *dp, uint32_t dsiz)
{
	Elf32_Ehdr ehdr;
	Elf32_Shdr shdr;
	uint32_t off;
	int i, len;

	if (lseek(fd, 0, SEEK_SET) != 0)
		return (-1);

	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
		return (-1);

	/* Read text and data sections to memory */
	for (i = 0; i < ehdr.e_shnum; i++) {
		if (lseek(fd, ehdr.e_shoff + sizeof(shdr) * i, SEEK_SET) !=
		    ehdr.e_shoff + sizeof(shdr) * i)
			return (-1);

		if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr))
			return (-1);

		if ((shdr.sh_flags & SHF_ALLOC) == 0)
			continue;
		if (shdr.sh_type != SHT_PROGBITS && shdr.sh_type != SHT_NOBITS)
			continue;

		/* Round up allocation to word-aligned size */
		len = (shdr.sh_size + 3) & ~3;

		/* Prepare for reading */
		if (lseek(fd, shdr.sh_offset, SEEK_SET) != shdr.sh_offset)
			return (-1);

		off = shdr.sh_addr - ehdr.e_entry;
		if (shdr.sh_flags & SHF_EXECINSTR) {
			if (off + len > tsiz)
				return (-1);
			if (read(fd, &tp[off], len) != len)
				return (-1);
		} else {
			if (off - tsiz + len > dsiz)
				return (-1);
			if (shdr.sh_type == SHT_NOBITS)
				memset(&dp[off - tsiz], 0, len);
			else if (read(fd, &dp[off - tsiz], len) != len)
				return (-1);
		}
	}

	return (0);
}
