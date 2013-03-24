/*
 * builtin-convert.c
 *
 * Builtin convert command: Convert a perf.data input file
 * to a callgrind profile data file.
 */

#include "builtin.h"

#include "util/util.h"
#include "util/color.h"
#include <linux/list.h>
#include "util/cache.h"
#include <linux/rbtree.h>
#include "util/symbol.h"

#include "perf.h"
#include "util/debug.h"

#include "util/evlist.h"
#include "util/evsel.h"
#include "util/annotate.h"
#include "util/event.h"
#include "util/parse-options.h"
#include "util/parse-events.h"
#include "util/thread.h"
#include "util/hist.h"
#include "util/session.h"
#include "util/tool.h"
#include "util/a2l.h"

#include <linux/bitmap.h>

struct perf_convert {
	struct perf_tool tool;
	char const *input_name;
	FILE *output_file;
	bool	   force;
	const char *cpu_list;
	DECLARE_BITMAP(cpu_bitmap, MAX_NR_CPUS);
	struct rb_root graph_root;
};

struct graph_node {
  u64 address;
  struct rb_node rb_node;
  struct map *map;
  struct symbol *sym;
  u64 hits[0];
};

static const char *last_source_name;
static unsigned last_line;
static u64 last_off;
static u64 nr_events;

static struct graph_node *get_graph_node(struct rb_root *root, struct map *map,
					 struct symbol *sym, u64 ip)
{
	struct rb_node **rb_node = &root->rb_node, *parent = NULL;
	struct graph_node *node;
	u64 address = sym ? sym->start : map ? map->start : ip;

	while (*rb_node){
	  	parent = *rb_node;
		node = rb_entry(parent, struct graph_node, rb_node);

		if (address < node->address)
		 	rb_node = &(*rb_node)->rb_left;
		else if (address > node->address)
		  	rb_node = &(*rb_node)->rb_right;
		else
		  	return node;
	}

	node = calloc(1, sizeof(*node) + nr_events * sizeof(node->hits[0]));
	node->map = map;
	node->sym = sym;
	node->address = address;

	rb_link_node(&node->rb_node, parent, rb_node);
	rb_insert_color(&node->rb_node, root);

	return node;
}

static int accumulate_sample(struct perf_evsel *evsel, struct addr_location *al, struct rb_root *graph_root)
{
	struct graph_node *node;
	int err = 0;

	node = get_graph_node(graph_root, al->map, al->sym, al->addr);
	node->hits[evsel->idx]++;

	if (node->sym != NULL) {
		struct annotation *notes = symbol__annotation(node->sym);
		if (notes->src == NULL && symbol__alloc_hist(node->sym) < 0)
			return -ENOMEM;

		err = symbol__inc_addr_samples(node->sym, node->map, evsel->idx, al->addr);
		if (err)
			return err;
	}

	hists__inc_nr_events(&evsel->hists, PERF_RECORD_SAMPLE);
	return 0;
}

static int process_sample_event(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample,
				struct perf_evsel *evsel,
				struct machine *machine)
{
	struct perf_convert *cnv = container_of(tool, struct perf_convert, tool);
	struct addr_location al;

	if (perf_event__preprocess_sample(event, machine, &al, sample,
					  symbol__annotate_init) < 0) {
		pr_warning("problem processing %d event, skipping it.\n",
			   event->header.type);
		return -1;
	}

	if (cnv->cpu_list && !test_bit(sample->cpu, cnv->cpu_bitmap))
		return 0;

	if (!al.filtered && accumulate_sample(evsel, &al, &cnv->graph_root)) {
		pr_warning("problem incrementing symbol count, skipping event\n");
		return -1;
	}

	return 0;
}

static int print_header(FILE *output, struct perf_session *session)
{
	struct perf_evsel *pos;

	fprintf(output, "positions: instr line\nevents:");
	list_for_each_entry(pos, &session->evlist->entries, node) {
		const char *evname = perf_evsel__name(pos);
		fprintf(output, " %s", evname);
	}
	fprintf(output, "\n");

	return 0;
}

static void print_function_header(FILE *output, struct symbol *sym,
				 struct map *map, struct annotation *notes,
				 u64 offset)
{
	int idx, ret;
	u64 function_start = map__rip_2objdump(map, sym->start);
	u64 address = function_start + offset;
	const char *filename;

	filename = "";
	addr2line(function_start, &filename, &last_line);

	fprintf(output, "ob=%s\n", map->dso->long_name);
	fprintf(output, "fl=%s\n", filename);
	fprintf(output, "fn=%s\n", sym->name);
	fprintf(output, "0 0\n");
	
	ret = addr2line(address, &last_source_name, &last_line);
	if (ret && strcmp(filename, last_source_name))
		fprintf(output, "fl=%s\n", last_source_name);

	fprintf(output, "%#" PRIx64 " %u", address, last_line);
	for (idx = 0; idx < notes->src->nr_histograms; idx++)
		fprintf(output, " %" PRIu64,
			annotation__histogram(notes, idx)->addr[offset]);

	fprintf(output, "\n");
	last_off = offset;
}

static inline bool events_have_samples(struct annotation *notes, u64 offset)
{
	int idx;

	for (idx = 0; idx < notes->src->nr_histograms; idx++)
		if (annotation__histogram(notes, idx)->addr[offset])
			return true;

	return false;
}

static void print_function_tail(FILE *output, struct symbol *sym,
				 struct map *map, struct annotation *notes,
				 u64 offset)
{
	int ret, idx;
	unsigned line;
	const char *filename = NULL;

	ret = addr2line(map__rip_2objdump(map, sym->start) + offset,
			&filename, &line);
	if (filename && last_source_name && strcmp(filename, last_source_name)) {
		fprintf(output, "fl=%s\n", filename);
		last_source_name = filename;
	}

	if (ret)
		fprintf(output, "+%" PRIu64 " %+d", offset - last_off,
			(int)(line - last_line));
	else
		fprintf(output, "+%" PRIu64 " %u", offset - last_off, line);

	for (idx = 0; idx < notes->src->nr_histograms; idx++) {
		u64 cnt = annotation__histogram(notes, idx)->addr[offset];
		fprintf(output, " %" PRIu64, cnt);
	}

	fprintf(output, "\n");
	last_off = offset;
	last_line = line;
}

static void print_function_summary(FILE *output, struct graph_node *node)
{
	unsigned idx;

	fprintf(output, "ob=%s\n", node->map ? node->map->dso->long_name : "");
	fprintf(output, "fl=\n");
	fprintf(output, "fn=%s\n", node->sym ? node->sym->name : "");
	fprintf(output, "0 0");

	for (idx = 0; idx < nr_events; idx++)
		fprintf(output, " %" PRIu64, node->hits[idx]);

	fprintf(output, "\n");
}

static void print_function(FILE *output, struct graph_node *node)
{
	struct annotation *notes;
	struct map *map = node->map;
	struct symbol *sym = node->sym;
	u64 sym_len, i;
	
	if(!map || !sym || addr2line_init(map->dso->long_name)){
		print_function_summary(output, node);
		return;
	}
	
	notes = symbol__annotation(sym);
	sym_len = sym->end - sym->start;

	for (i = 0; i < sym_len; i++) {
		if (events_have_samples(notes, i)) {
			print_function_header(output, sym, map, notes, i);
			break;
		}
	}

	for (++i; i < sym_len; i++) {
		if (events_have_samples(notes, i))
			print_function_tail(output, sym, map, notes, i);
	}
}

static void print_functions(FILE *output, struct rb_node *rb_node){
	struct graph_node *node;

	if(!rb_node)
		return;

	node = rb_entry(rb_node, struct graph_node, rb_node);
	print_functions(output, rb_node->rb_left);
	print_function(output, node);
	print_functions(output, rb_node->rb_right);
}

static int __cmd_convert(struct perf_convert *cnv)
{
	int ret;
	struct perf_session *session;

	session = perf_session__new(cnv->input_name, O_RDONLY,
				    cnv->force, false, &cnv->tool);
	if (session == NULL)
		return -ENOMEM;

	nr_events = session->evlist->nr_entries;

	if (cnv->cpu_list) {
		ret = perf_session__cpu_bitmap(session, cnv->cpu_list,
					       cnv->cpu_bitmap);
		if (ret)
			goto out_delete;
	}

	ret = perf_session__process_events(session, &cnv->tool);
	if (ret)
		goto out_delete;

	ret = print_header(cnv->output_file, session);
	if (ret)
		goto out_delete;

	print_functions(cnv->output_file, cnv->graph_root.rb_node);

out_delete:
	/*
	 * Speed up the exit process, for large files this can
	 * take quite a while.
	 *
	 * XXX Enable this when using valgrind or if we ever
	 * librarize this command.
	 *
	 * Also experiment with obstacks to see how much speed
	 * up we'll get here.
	 *
	 * perf_session__delete(session);
	 */
	return ret;
}

static const char * const convert_usage[] = {
	"perf convert [<options>]",
	NULL
};

int cmd_convert(int argc, const char **argv, const char *prefix __maybe_unused)
{
	const char *output_filename = "callgrind.out";
	struct perf_convert convert = {
		.tool = {
			.sample	= process_sample_event,
			.mmap	= perf_event__process_mmap,
			.comm	= perf_event__process_comm,
			.exit	= perf_event__process_exit,
			.fork	= perf_event__process_fork,
			.ordered_samples = true,
			.ordering_requires_timestamps = true,
		},
		.graph_root = RB_ROOT
	};
	const struct option options[] = {
	OPT_STRING('i', "input", &convert.input_name, "file",
		    "input file name"),
	OPT_STRING('o', "output", &output_filename, "output", "output filename, "
			"default is callgrind.out"),
	OPT_STRING('d', "dsos", &symbol_conf.dso_list_str, "dso[,dso...]",
		   "only consider symbols in these dsos"),
	OPT_BOOLEAN('f', "force", &convert.force, "don't complain, do it"),
	OPT_STRING('k', "vmlinux", &symbol_conf.vmlinux_name,
		   "file", "vmlinux pathname"),
	OPT_BOOLEAN('m', "modules", &symbol_conf.use_modules,
		    "load module symbols - WARNING: use only with -k and LIVE kernel"),
	OPT_STRING('C', "cpu", &convert.cpu_list, "cpu", "list of cpus to profile"),
	OPT_STRING(0, "symfs", &symbol_conf.symfs, "directory",
		   "Look for files with symbols relative to this directory"),
	OPT_END()
	};

	argc = parse_options(argc, argv, options, convert_usage, 0);

	symbol_conf.priv_size = sizeof(struct annotation);
	symbol_conf.try_vmlinux_path = true;

	convert.output_file = fopen(output_filename, "w");

	if (!convert.output_file) {
		fprintf(stderr, "Cannot open %s for output\n", output_filename);
		return -1;
	}

	if (symbol__init() < 0)
		return -1;

	return __cmd_convert(&convert);
}
