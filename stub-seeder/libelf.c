
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// 2
uint64_t	hash_words[] = {0x0123456789abcdef, 0xdeadbeefcafebabe,
		0xdeadc0dedeadbabe};

// 3
char		string_table[] = {
	/* Offset 0 */ '\0',
	/* Offset 1 */ '.',
	'f',
	'o',
	'o',
	'\0',
	/* Offset 6 */ '.',
	's',
	'h',
	's',
	't',
	'r',
	't',
	'a',
	'b',
	'\0'};

char		mkstemp_template[] = "test.libelf.XXXXXX";
int	main(int argc, char **argv)
{
	char		*target;
	int			fd;
	Elf			*e;
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdr;
	Elf_Scn		*scn;
	Elf_Data	*data;
	Elf64_Shdr	*shdr;

	if (argc < 2)
		fd = mkstemp(mkstemp_template);
	else
		fd = open(argv[1], O_WRONLY | O_CREAT, 0777);
	if (fd < 0)
		errx(EXIT_FAILURE, "failed to open `%s`: %s\n", target,
			strerror(errno));
	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		close(fd);
		errx(EXIT_FAILURE, "ELF lib init fail: %s\n", elf_errmsg(-1));
	}
	// 5
	e = elf_begin(fd, ELF_C_WRITE, NULL);
	if (!e)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf_begin() failed: %s\n", elf_errmsg(-1));
	}
	// 6
	ehdr = elf64_newehdr(e);
	if (!ehdr)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf64_newehdr() failed: %s\n", elf_errmsg(-1));
	}
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_machine = EM_X86_64;
	ehdr->e_type = ET_EXEC;
	// 7
	phdr = elf64_newphdr(e, 1);
	if (!phdr)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf64_newphdr() failed: %s\n", elf_errmsg(-1));
	}
	// 8
	scn = elf_newscn(e);
	if (!scn)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf_newscn() failed: %s\n", elf_errmsg(-1));
	}
	data = elf_newdata(scn);
	if (!data)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf_newdata() failed: %s\n", elf_errmsg(-1));
	}
	data->d_align = 8;
	data->d_off = 0LL;
	data->d_buf = hash_words;
	data->d_type = ELF_T_WORD;
	data->d_size = sizeof(hash_words);
	data->d_version = EV_CURRENT;
	shdr = elf64_getshdr(scn);
	if (!shdr)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf64_getshdr() failed: %s\n", elf_errmsg(-1));
	}
	shdr->sh_name = 1;
	shdr->sh_type = SHT_HASH;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_entsize = 0;
	// 9
	scn = elf_newscn(e);
	if (!scn)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf_newscn() failed: %s\n", elf_errmsg(-1));
	}
	data = elf_newdata(scn);
	if (!data)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf_newdata() failed: %s\n", elf_errmsg(-1));
	}
	data->d_align = 1;
	data->d_buf = string_table;
	data->d_off = 0LL;
	data->d_size = sizeof(string_table);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	shdr = elf64_getshdr(scn);
	if (!shdr)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf64_getshdr() failed: %s\n", elf_errmsg(-1));
	}
	shdr->sh_name = 6;
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = SHF_STRINGS | SHF_ALLOC;
	shdr->sh_entsize = 0;
	// 10
	ehdr->e_shstrndx = elf_ndxscn(scn);
	// 11
	if (elf_update(e, ELF_C_NULL) < 0)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf_update() failed: %s\n", elf_errmsg(-1));
	}
	phdr->p_type = PT_PHDR;
	phdr->p_offset = ehdr->e_phoff;
	phdr->p_filesz = elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);
	if (elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY) == 0)
	{
		fprintf(stderr, "elf_flagphdr() failed: %s\n", elf_errmsg(-1));
	}
	// 12
	if (elf_update(e, ELF_C_WRITE) < 0)
	{
		close(fd);
		errx(EXIT_FAILURE, "elf_update() failed: %s\n", elf_errmsg(-1));
	}
	elf_end(e);
	close(fd);
	return (EXIT_SUCCESS);
}
