#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

void print_scn(char *data, size_t data_length)
{
	if (!data)
	{
		printf("(null)");
		return;
	}
	for (size_t i = 0; i < data_length; i++)
	{
		char c = data[i];
		printf("%c", isprint(c) ? c : '.');
	}
}

int main(int argc, char **argv)
{
	char *target;
	int fd;
	struct stat sb;
	char *file_data;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;

	if (argc < 2)
		target = "/proc/self/exe";
	else
		target = argv[1];
	fd = open(target, O_RDONLY);
	if (fd < 0)
	{
		perror("open");
		exit(EXIT_FAILURE);
	}
	if (fstat(fd, &sb) < 0)
	{
		perror("fstat");
		exit(EXIT_FAILURE);
	}
	file_data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_data == MAP_FAILED)
	{
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	ehdr = (Elf64_Ehdr *)file_data;
	__builtin_dump_struct(ehdr, printf);
	shdr = (Elf64_Shdr *)(file_data + ehdr->e_shoff);
	for (short i = 0; i < ehdr->e_shnum; i++)
	{
		printf("@ %p [%d]:\n", (void *)ehdr->e_shoff + (i * sizeof(Elf64_Shdr)), i);
		__builtin_dump_struct(&shdr[i], printf);
		print_scn(file_data + shdr[i].sh_offset, shdr[i].sh_size);
		printf("\n");
	}

	munmap(file_data, sb.st_size);
	close(fd);
	return (0);
}
