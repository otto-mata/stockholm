#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>

int is_trailing_table_section(const char *name)
{
	if (!name)
		return 0;
	return (strcmp(name, ".symtab") == 0 ||
			strcmp(name, ".strtab") == 0 ||
			strcmp(name, ".shstrtab") == 0);
}

void add_custom_section(const char *in_filename, const char *out_filename,
						const char *section_name, const char *payload, size_t payload_length)
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

	// Force libelf to use our explicit file offsets
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

	size_t new_shstr_offset = 0;
	off_t max_regular_offset = 0;

	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(src_elf, scn)) != NULL)
	{
		size_t idx = elf_ndxscn(scn);
		GElf_Shdr shdr;
		gelf_getshdr(scn, &shdr);

		char *sec_name = elf_strptr(src_elf, shstrndx, shdr.sh_name);

		if (is_trailing_table_section(sec_name))
		{
			continue;
		}

		Elf_Scn *dst_scn = elf_newscn(dst_elf);
		Elf_Data *src_data = elf_getdata(scn, NULL);
		Elf_Data *dst_data = elf_newdata(dst_scn);

		if (src_data)
		{
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
			if (end_off > max_regular_offset)
				max_regular_offset = end_off;
		}
	}

	// Pass 2: Insert the custom section right after regular sections
	off_t custom_sec_offset = max_regular_offset; // 1-byte aligned placement

	Elf_Scn *custom_scn = elf_newscn(dst_elf);
	Elf_Data *custom_data = elf_newdata(custom_scn);

	custom_data->d_buf = (void *)payload;
	custom_data->d_size = payload_length;
	custom_data->d_type = ELF_T_BYTE;
	custom_data->d_align = 1; // 1-byte alignment requested
	custom_data->d_off = 0;
	custom_data->d_version = EV_CURRENT;

	GElf_Shdr custom_shdr;
	memset(&custom_shdr, 0, sizeof(GElf_Shdr));
	custom_shdr.sh_name = 0; // Updated in Pass 3 once .shstrtab is expanded
	custom_shdr.sh_type = SHT_PROGBITS;
	custom_shdr.sh_flags = 0;
	custom_shdr.sh_addralign = 1;
	custom_shdr.sh_offset = custom_sec_offset;
	custom_shdr.sh_size = payload_length;

	gelf_update_shdr(custom_scn, &custom_shdr);

	// Current write head now points after payload
	off_t current_offset = custom_sec_offset + payload_length;

	// Pass 3: Re-insert trailing table sections (.symtab, .strtab, .shstrtab) with recalculated offsets
	scn = NULL;
	while ((scn = elf_nextscn(src_elf, scn)) != NULL)
	{
		size_t idx = elf_ndxscn(scn);
		GElf_Shdr shdr;
		gelf_getshdr(scn, &shdr);

		char *sec_name = elf_strptr(src_elf, shstrndx, shdr.sh_name);
		if (!is_trailing_table_section(sec_name))
		{
			continue;
		}

		Elf_Scn *dst_scn = elf_newscn(dst_elf);
		Elf_Data *src_data = elf_getdata(scn, NULL);
		Elf_Data *dst_data = elf_newdata(dst_scn);

		// Maintain alignment requirements for structural tables
		size_t align = shdr.sh_addralign ? shdr.sh_addralign : 8;
		current_offset = (current_offset + (align - 1)) & ~(align - 1);
		shdr.sh_offset = current_offset;
		if (shdr.sh_link)
			shdr.sh_link++;
		if (idx == shstrndx && src_data)
		{
			// Expand .shstrtab to fit the new section name
			size_t name_len = strlen(section_name) + 1;
			new_shstr_offset = src_data->d_size;
			size_t new_shstr_size = new_shstr_offset + name_len;

			char *new_buf = malloc(new_shstr_size);
			if (src_data->d_buf && src_data->d_size > 0)
			{
				memcpy(new_buf, src_data->d_buf, src_data->d_size);
			}
			memcpy(new_buf + new_shstr_offset, section_name, name_len);

			dst_data->d_buf = new_buf;
			dst_data->d_size = new_shstr_size;
			dst_data->d_type = src_data->d_type;
			dst_data->d_align = src_data->d_align;
			dst_data->d_version = src_data->d_version;
			shdr.sh_size = new_shstr_size;

			allocated_buffers = realloc(allocated_buffers, sizeof(void *) * (alloc_count + 1));
			allocated_buffers[alloc_count++] = new_buf;

			// Link section name in custom section header
			custom_shdr.sh_name = new_shstr_offset;
			gelf_update_shdr(custom_scn, &custom_shdr);
		}
		else if (src_data)
		{
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
		current_offset += shdr.sh_size;
	}

	// Place the Section Header Table at the end, aligned to 8 bytes
	current_offset = (current_offset + 7) & ~7;
	dst_ehdr.e_shoff = current_offset;
	dst_ehdr.e_shstrndx = shstrndx + 1;
	gelf_update_ehdr(dst_elf, &dst_ehdr);

	if (elf_update(dst_elf, ELF_C_WRITE) < 0)
		fprintf(stderr, "elf_update write failed: %s\n", elf_errmsg(-1));
	else
		printf("Successfully added section '%s' before tables in %s!\n", section_name, out_filename);

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
		printf("Usage: %s <input_elf> <output_elf>\n", argv[0]);
		return 1;
	}

	const char *data_to_embed = "Hello! Embedded payload data.\n";
	add_custom_section(argv[1], argv[2], ".custom_payload", data_to_embed, strlen(data_to_embed));

	return 0;
}
