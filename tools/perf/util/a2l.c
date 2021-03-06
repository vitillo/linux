/* based on addr2line */

#define PACKAGE "perf"

#include <linux/kernel.h>

#include <bfd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "a2l.h"

static const char *filename;
static const char *functionname;
static const char *last_opened_file;
static unsigned int line;
static asymbol **syms;
static bfd_vma pc;
static bfd_boolean found;
static bfd *abfd;

static void bfd_nonfatal(const char *string)
{
	const char *errmsg;

	errmsg = bfd_errmsg(bfd_get_error());
	fflush(stdout);
	if (string)
		pr_warning("%s: %s\n", string, errmsg);
	else
		pr_warning("%s\n", errmsg);
}

static int bfd_fatal(const char *string)
{
	bfd_nonfatal(string);
	return -1;
}

static int slurp_symtab(void)
{
	long storage;
	long symcount;
	bfd_boolean dynamic = FALSE;

	if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0)
		return bfd_fatal(bfd_get_filename(abfd));

	storage = bfd_get_symtab_upper_bound(abfd);
	if (storage == 0) {
		storage = bfd_get_dynamic_symtab_upper_bound(abfd);
		dynamic = TRUE;
	}
	if (storage < 0)
		return bfd_fatal(bfd_get_filename(abfd));

	syms = (asymbol **) malloc(storage);
	if (dynamic)
		symcount = bfd_canonicalize_dynamic_symtab(abfd, syms);
	else
		symcount = bfd_canonicalize_symtab(abfd, syms);

	if (symcount < 0)
		return bfd_fatal(bfd_get_filename(abfd));

	return 0;
}

static void find_address_in_section(bfd *mybfd, asection *section,
				    void *data ATTRIBUTE_UNUSED)
{
	bfd_vma vma;
	bfd_size_type size;
	(void)mybfd;

	if (found)
		return;

	if ((bfd_get_section_flags(abfd, section) & SEC_ALLOC) == 0)
		return;

	vma = bfd_get_section_vma(abfd, section);
	if (pc < vma)
		return;

	size = bfd_get_section_size(section);
	if (pc >= vma + size)
		return;

	found = bfd_find_nearest_line(abfd, section, syms, pc - vma,
			&filename, &functionname, &line);
}

int addr2line_init(const char *file_name)
{
	if(last_opened_file && !strcmp(last_opened_file, file_name))
		return 0;
	else
		addr2line_cleanup();

	abfd = bfd_openr(file_name, NULL);
	if (abfd == NULL)
		return -1;

	if (!bfd_check_format(abfd, bfd_object))
		return bfd_fatal(bfd_get_filename(abfd));

	last_opened_file = file_name;
	return slurp_symtab();

}

void addr2line_cleanup(void)
{
	if (syms != NULL) {
		free(syms);
		syms = NULL;
	}

	if (abfd)
		bfd_close(abfd);

	line = found = 0;
	last_opened_file = NULL;
	abfd = 0;
}

int addr2line_inline(const char **file, unsigned *line_nr)
{
	return bfd_find_inliner_info(abfd, file, &functionname, line_nr);
}

int addr2line(unsigned long addr, const char **file, unsigned *line_nr)
{
	found = 0;
	pc = addr;
	bfd_map_over_sections(abfd, find_address_in_section, NULL);

	if (found) {
		*file = filename ? filename : "";
		*line_nr = line;
		return found;
	}

	return 0;
}
