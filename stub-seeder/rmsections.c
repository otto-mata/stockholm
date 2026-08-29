#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>

void remove_custom_section(const char *in_filename, const char *out_filename, const char *target_sec_name)
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

	Elf *src_elf = elf_begin(in_fd, ELF_C_READ, NULL);
	if (!src_elf)
	{
		fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
		close(in_fd);
		exit(EXIT_FAILURE);
	}

	size_t shstrndx;
	if (elf_getshdrstrndx(src_elf, &shstrndx) != 0)
	{
		fprintf(stderr, "Failed to get shstrndx: %s\n", elf_errmsg(-1));
		elf_end(src_elf);
		close(in_fd);
		exit(EXIT_FAILURE);
	}

	// Step 1: Count remaining sections & build index mapping table
	size_t src_shnum = 0;
	elf_getshdrnum(src_elf, &src_shnum);

	size_t *index_map = calloc(src_shnum, sizeof(size_t));
	Elf_Scn *scn = NULL;
	size_t new_index = 0;
	int section_found = 0;

	while ((scn = elf_nextscn(src_elf, scn)) != NULL)
	{
		size_t old_index = elf_ndxscn(scn);
		GElf_Shdr shdr;
		gelf_getshdr(scn, &shdr);

		const char *name = elf_strptr(src_elf, shstrndx, shdr.sh_name);
		if (name && strcmp(name, target_sec_name) == 0)
		{
			section_found = 1;
			index_map[old_index] = 0; // Set to 0 to indicate removed section
		}
		else
		{
			index_map[old_index] = new_index++;
		}
	}

	if (!section_found)
	{
		fprintf(stderr, "Section '%s' not found in file.\n", target_sec_name);
		free(index_map);
		elf_end(src_elf);
		close(in_fd);
		exit(EXIT_FAILURE);
	}

	// Step 2: Prepare output file and clone ELF Header
	int out_fd = open(out_filename, O_RDWR | O_CREAT | O_TRUNC, 0755);
	if (out_fd < 0)
	{
		perror("Failed to open output file");
		free(index_map);
		elf_end(src_elf);
		close(in_fd);
		exit(EXIT_FAILURE);
	}

	Elf *dst_elf = elf_begin(out_fd, ELF_C_WRITE, NULL);
	GElf_Ehdr src_ehdr, dst_ehdr;
	gelf_getehdr(src_elf, &src_ehdr);

	gelf_newehdr(dst_elf, gelf_getclass(src_elf));
	gelf_getehdr(dst_elf, &dst_ehdr);
	memcpy(&dst_ehdr, &src_ehdr, sizeof(GElf_Ehdr));

	// Update ELF header's section header string table index mapping
	dst_ehdr.e_shstrndx = index_map[src_ehdr.e_shstrndx];

	// Step 3: Copy only non-matching sections and remap internal section links
	scn = NULL;
	while ((scn = elf_nextscn(src_elf, scn)) != NULL)
	{
		size_t old_index = elf_ndxscn(scn);
		if (index_map[old_index] == 0 && old_index != 0)
		{
			continue; // Skip the target section
		}

		Elf_Scn *dst_scn = elf_newscn(dst_elf);
		GElf_Shdr shdr;
		gelf_getshdr(scn, &shdr);

		// Remap section header linkage (sh_link and sh_info)
		if (shdr.sh_link < src_shnum)
		{
			shdr.sh_link = index_map[shdr.sh_link];
		}
		if ((shdr.sh_flags & SHF_INFO_LINK) && shdr.sh_info < src_shnum)
		{
			shdr.sh_info = index_map[shdr.sh_info];
		}

		Elf_Data *src_data = elf_getdata(scn, NULL);
		Elf_Data *dst_data = elf_newdata(dst_scn);
		if (src_data)
		{
			*dst_data = *src_data;
		}

		gelf_update_shdr(dst_scn, &shdr);
	}

	gelf_update_ehdr(dst_elf, &dst_ehdr);
	elf_flagelf(dst_elf, ELF_C_SET, ELF_F_DIRTY);

	if (elf_update(dst_elf, ELF_C_WRITE) < 0)
	{
		fprintf(stderr, "elf_update failed: %s\n", elf_errmsg(-1));
	}
	else
	{
		printf("Successfully removed section '%s' -> saved to %s\n", target_sec_name, out_filename);
	}

	// Cleanup
	free(index_map);
	elf_end(src_elf);
	elf_end(dst_elf);
	close(in_fd);
	close(out_fd);
}

int main(int argc, char **argv)
{
	if (argc < 3)
	{
		printf("Usage: %s <input_elf> <output_elf> [section_name]\n", argv[0]);
		return 1;
	}

	const char *sec_name = (argc >= 4) ? argv[3] : ".my_data";
	remove_custom_section(argv[1], argv[2], sec_name);

	return 0;
}
