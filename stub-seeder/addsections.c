#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <ctype.h>

#define LOAD_ADDRESS 0x0000000000400000

//! FIXME: add_section ajoute cette grosse merde de content a l'adresse 0

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

size_t add_section(Elf *src_elf, Elf *dst_elf, size_t name_offset, size_t section_data_offset,
				   const char *sec_name, const char *payload, size_t payload_len)
{

	// 4. Create and populate the NEW custom section
	Elf_Scn *new_scn = elf_newscn(dst_elf);
	Elf_Data *new_data = elf_newdata(new_scn);

	new_data->d_buf = (void *)payload;
	new_data->d_size = payload_len;
	new_data->d_type = ELF_T_BYTE;
	new_data->d_align = 1;
	new_data->d_version = EV_CURRENT;

	GElf_Shdr new_shdr;
	memset(&new_shdr, 0, sizeof(GElf_Shdr));
	new_shdr.sh_name = name_offset;	 // Offset inside .shstrtab
	new_shdr.sh_type = SHT_PROGBITS; // Program data
	new_shdr.sh_flags = 0;			 // Equivalent to 'alloc' flag
	new_shdr.sh_addralign = 1;
	new_shdr.sh_size = payload_len;
	new_shdr.sh_offset = section_data_offset;

	gelf_update_shdr(new_scn, &new_shdr);
	return section_data_offset + payload_len;
}

void add_custom_section(const char *in_filename, const char *out_filename, const char *section_name, const char *payload, size_t payload_length)
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
	Elf_Data important_sections_data[3];
	GElf_Shdr important_sections_headers[3];

	Elf_Scn *scn = NULL;
	size_t new_index = 0;

	while ((scn = elf_nextscn(src_elf, scn)) != NULL)
	{
		size_t old_index = elf_ndxscn(scn);
		GElf_Shdr shdr;
		Elf_Data *shdata;
		gelf_getshdr(scn, &shdr);

		void *dbuf_cpy;
		const char *name = elf_strptr(src_elf, shstrndx, shdr.sh_name);
		if (!name)
			continue;
		printf("section %s\n", name);
		__builtin_dump_struct(&shdr, printf);
		if (strcmp(name, ".symtab") == 0)
		{
			shdata = elf_getdata(scn, NULL);
			dbuf_cpy = malloc(shdata->d_size);
			memmove(dbuf_cpy, shdata->d_buf, shdata->d_size);
			shdata->d_buf = dbuf_cpy;
			memmove(&important_sections_data[0], shdata, sizeof(*shdata));
			memmove(&important_sections_headers[0], &shdr, sizeof(shdr));
			printf(".symtab: %zu\n", old_index);
		}
		else if (strcmp(name, ".strtab") == 0)
		{
			shdata = elf_getdata(scn, NULL);
			dbuf_cpy = malloc(shdata->d_size);
			memmove(dbuf_cpy, shdata->d_buf, shdata->d_size);
			shdata->d_buf = dbuf_cpy;
			memmove(&important_sections_data[1], shdata, sizeof(*shdata));
			memmove(&important_sections_headers[1], &shdr, sizeof(shdr));
			printf(".strtab: %zu\n", old_index);
		}
		else if (strcmp(name, ".shstrtab") == 0)
		{
			shdata = elf_getdata(scn, NULL);
			dbuf_cpy = malloc(shdata->d_size);
			memmove(dbuf_cpy, shdata->d_buf, shdata->d_size);
			shdata->d_buf = dbuf_cpy;
			memmove(&important_sections_data[2], shdata, sizeof(*shdata));
			memmove(&important_sections_headers[2], &shdr, sizeof(shdr));
			printf(".shstrtab: %zu\n", old_index);
		}
		else
			index_map[old_index] = new_index++;
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

	memmove(&dst_ehdr, &src_ehdr, sizeof(GElf_Ehdr));

	GElf_Phdr src_phdr;
	GElf_Phdr dst_phdr;
	gelf_newphdr(dst_elf, src_ehdr.e_phnum);
	for (Elf64_Half i = 0; i < src_ehdr.e_phnum; i++)
	{
		gelf_getphdr(src_elf, i, &src_phdr);
		if (!gelf_update_phdr(dst_elf, i, &src_phdr))
		{
			printf("error upating program header %d: %s\n", i, elf_errmsg(-1));
		}
	}

	// Update ELF header's section header string table index mapping

	// Step 3: Copy only non-matching sections and remap internal section links
	scn = NULL;
	GElf_Shdr orig_shdr;
	while ((scn = elf_nextscn(src_elf, scn)) != NULL)
	{
		size_t old_index = elf_ndxscn(scn);
		if (old_index > shstrndx - 3)
		{
			continue; // Skip the target section
		}

		Elf_Scn *dst_scn = elf_newscn(dst_elf);
		gelf_getshdr(scn, &orig_shdr);
		const char *name = elf_strptr(src_elf, shstrndx, orig_shdr.sh_name);
		printf("copying `%s`\n", name);
		__builtin_dump_struct(&orig_shdr, printf);
		if ((orig_shdr.sh_flags & SHF_INFO_LINK) && orig_shdr.sh_info < src_shnum)
		{
			orig_shdr.sh_info = index_map[orig_shdr.sh_info];
		}

		Elf_Data *src_data = elf_getdata(scn, NULL);
		Elf_Data *dst_data = elf_newdata(dst_scn);
		if (src_data)
		{
			*dst_data = *src_data;
		}

		if (!gelf_update_shdr(dst_scn, &orig_shdr))
			fprintf(stderr, "copy 1 gelf_update_shdr() failed: %s\n", elf_errmsg(-1));
	}

	gelf_update_ehdr(dst_elf, &dst_ehdr);
	elf_flagelf(dst_elf, ELF_C_SET, ELF_F_LAYOUT);
	if (elf_update(dst_elf, ELF_C_WRITE) < 0)
	{
		fprintf(stderr, "elf_update 1 failed: %s\n", elf_errmsg(-1));
	}
	Elf_Data *shstr_data = &important_sections_data[2];

	size_t start_offset_for_special_sections = add_section(src_elf, dst_elf, shstr_data->d_size,
														   orig_shdr.sh_offset + orig_shdr.sh_size,
														   section_name, payload, payload_length);

	gelf_update_ehdr(dst_elf, &dst_ehdr);
	size_t name_offset = shstr_data->d_size;
	size_t name_len = strlen(section_name) + 1;

	char *new_shstr_buf = malloc(name_offset + name_len);
	memmove(new_shstr_buf, shstr_data->d_buf, name_offset);
	memmove(new_shstr_buf + name_offset, section_name, name_len);

	shstr_data->d_buf = new_shstr_buf;
	shstr_data->d_size = name_offset + name_len;
	important_sections_headers[2].sh_size = shstr_data->d_size;

	__builtin_dump_struct(&important_sections_headers[2], printf);
	__builtin_dump_struct(&important_sections_data[2], printf);
	dst_ehdr.e_shstrndx = src_shnum;
	src_shnum++;
	printf("shstrndx: %zu\n", shstrndx);
	for (size_t i = 0; i < 3; i++)
	{
		Elf_Scn *dst_scn = elf_newscn(dst_elf);
		GElf_Shdr shdr = important_sections_headers[i];
		shdr.sh_offset += payload_length;
		const char *name = elf_strptr(src_elf, shstrndx, shdr.sh_name);
		printf("copying `%s`\n", name);
		if (shdr.sh_link > src_shnum - 4)
		{
			shdr.sh_link++;
		}
		if ((shdr.sh_flags & SHF_INFO_LINK) && shdr.sh_info < src_shnum)
		{
			shdr.sh_info = index_map[shdr.sh_info];
		}
		Elf_Data *src_data = &important_sections_data[i];

		Elf_Data *dst_data = elf_newdata(dst_scn);
		if (src_data)
		{

			printf("section content:\n");
			print_scn(src_data->d_buf, src_data->d_size);
			printf("\n");
			*dst_data = *src_data;
		}
		shdr.sh_size = src_data->d_size;
		printf("section size: %zu (0x%lX)\n", shdr.sh_size, shdr.sh_size);
		if (!gelf_update_shdr(dst_scn, &shdr))
			fprintf(stderr, "copy 2 gelf_update_shdr() failed: %s\n", elf_errmsg(-1));
	}

	gelf_update_ehdr(dst_elf, &dst_ehdr);
	elf_flagelf(dst_elf, ELF_C_SET, ELF_F_LAYOUT);

	if (elf_update(dst_elf, ELF_C_WRITE) < 0)
	{
		fprintf(stderr, "elf_update failed: %s\n", elf_errmsg(-1));
	}
	else
	{
		printf("Successfully added section '%s' -> saved to %s\n", section_name, out_filename);
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
		printf("Usage: %s <input_elf> <output_elf>\n", argv[0]);
		return 1;
	}

	const char *data_to_embed = "Hello! This is custom binary payload data embedded via libelf.\n";
	add_custom_section(argv[1], argv[2], ".mydata", data_to_embed, strlen(data_to_embed) + 1);

	return 0;
}
