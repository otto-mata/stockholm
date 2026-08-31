#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <err.h>
#include <errno.h>
#include <sys/stat.h>

static const char *ext = ".patch";

void patch_dot_key_section(const char *in_filename, const char *out_filename,
						   const char *payload, size_t payload_length)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	int in_fd = open(in_filename, O_RDONLY, 0);
	if (in_fd < 0)
	{
		perror("Failed to open input file");
		exit(EXIT_FAILURE);
	}

	int out_fd = open(out_filename, O_RDWR | O_CREAT | O_TRUNC, 0755);
	if (out_fd < 0)
	{
		perror("Failed to open output file");
		close(in_fd);
		exit(EXIT_FAILURE);
	}

	Elf *src_elf = elf_begin(in_fd, ELF_C_READ, NULL);
	Elf *dst_elf = elf_begin(out_fd, ELF_C_WRITE, NULL);

	elf_flagelf(dst_elf, ELF_C_SET, ELF_F_LAYOUT);

	GElf_Ehdr src_ehdr;
	gelf_getehdr(src_elf, &src_ehdr);
	gelf_newehdr(dst_elf, gelf_getclass(src_elf));

	GElf_Ehdr dst_ehdr;
	gelf_getehdr(dst_elf, &dst_ehdr);
	memcpy(&dst_ehdr, &src_ehdr, sizeof(GElf_Ehdr));

	if (src_ehdr.e_phnum > 0)
	{
		gelf_newphdr(dst_elf, src_ehdr.e_phnum);
		for (size_t i = 0; i < src_ehdr.e_phnum; i++)
		{
			GElf_Phdr phdr;
			gelf_getphdr(src_elf, i, &phdr);
			gelf_update_phdr(dst_elf, i, &phdr);
		}
	}

	size_t shstrndx;
	if (elf_getshdrstrndx(src_elf, &shstrndx) != 0)
	{
		fprintf(stderr, "Failed to get shstrndx: %s\n", elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	void **allocated_buffers = NULL;
	size_t alloc_count = 0;

	off_t current_offset = 0;

	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(src_elf, scn)) != NULL)
	{
		GElf_Shdr shdr;
		gelf_getshdr(scn, &shdr);

		char *sec_name = elf_strptr(src_elf, shstrndx, shdr.sh_name);

		Elf_Scn *dst_scn = elf_newscn(dst_elf);
		Elf_Data *src_data = elf_getdata(scn, NULL);
		Elf_Data *dst_data = elf_newdata(dst_scn);

		if (src_data)
		{

			if (strcmp(sec_name, ".key") == 0)
			{
				src_data->d_buf = (void *)payload;
				src_data->d_size = payload_length;
			}

			*dst_data = *src_data;
			if (src_data->d_buf != NULL && src_data->d_size > 0)
			{
				void *buf_copy = malloc(src_data->d_size);
				memcpy(buf_copy, src_data->d_buf, src_data->d_size);
				dst_data->d_buf = buf_copy;
				allocated_buffers = realloc(allocated_buffers, sizeof(void *) * (alloc_count + 1));
				allocated_buffers[alloc_count++] = buf_copy;
			}
		}

		gelf_update_shdr(dst_scn, &shdr);

		if (shdr.sh_type != SHT_NOBITS)
		{
			off_t end_off = shdr.sh_offset + shdr.sh_size;
			if (end_off > current_offset)
				current_offset = end_off;
		}
	}

	current_offset = (current_offset + 7) & ~7;
	dst_ehdr.e_shoff = current_offset;
	dst_ehdr.e_shstrndx = shstrndx;
	gelf_update_ehdr(dst_elf, &dst_ehdr);

	if (elf_update(dst_elf, ELF_C_WRITE) < 0)
		fprintf(stderr, "elf_update write failed: %s\n", elf_errmsg(-1));
	else
		printf("Patched %s!\n", out_filename);

	for (size_t i = 0; i < alloc_count; i++)
	{
		free(allocated_buffers[i]);
	}
	free(allocated_buffers);

	elf_end(src_elf);
	elf_end(dst_elf);
	close(in_fd);
	close(out_fd);
}

int main(int argc, char **argv)
{
	if (argc < 3)
	{
		printf("Usage: %s <input_elf> <pem>\n", argv[0]);
		return 1;
	}
	int fd = open(argv[2], O_RDONLY);
	if (fd < 0)
		errx(1, "failed to open PEM file: %s\n", strerror(errno));
	struct stat fst;
	if (fstat(fd, &fst))
		errx(1, "failed to stat PEM file: %s\n", strerror(errno));
	if (fst.st_size > 4095)
	{
		close(fd);
		errx(1, "data cannot be longer than 4095 bytes (file is %zu bytes)\n", fst.st_size);
	}

	char *data = malloc(fst.st_size + 1);
	ssize_t rb = 0;
	size_t total = 0;
	while ((rb = read(fd, &data[rb], fst.st_size)) > 0 && total < 4095)
		total += rb;

	size_t filename_sz = strlen(argv[1]);

	char *patched_name = malloc(filename_sz + strlen(ext) + 1);
	strcat(patched_name, argv[1]);
	strcat(patched_name, ext);
	patched_name[filename_sz + strlen(ext)] = 0;
	patch_dot_key_section(argv[1], patched_name, data, strlen(data));

	return 0;
}
