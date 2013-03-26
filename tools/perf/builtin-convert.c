/*
 * builtin-convert.c
 *
 * Builtin convert command: Convert a perf.data input file
 * to a set of callgrind profile data files.
 */

#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/bitmap.h>

#include "util/util.h"
#include "util/cache.h"
#include "util/symbol.h"
#include "util/evlist.h"
#include "util/evsel.h"
#include "util/annotate.h"
#include "util/event.h"
#include "util/parse-options.h"
#include "util/parse-events.h"
#include "util/thread.h"
#include "util/session.h"
#include "util/tool.h"
#include "util/a2l.h"

#include "builtin.h"
#include "perf.h"

struct perf_convert {
	struct perf_tool tool;
	char const *input_name;
	char const *output_prefix;
	bool	   force;
	const char *cpu_list;
	DECLARE_BITMAP(cpu_bitmap, MAX_NR_CPUS);
};

struct stats {
	u64 hits;
	bool has_callees;
};

struct graph_node {
	const char *filename;
	struct rb_node rb_node;
	struct map *map;
	struct symbol *sym;
	struct rb_root callees;
	struct stats stats[0];
};

struct callee {
	struct rb_node rb_node;
	struct map *map;
	struct symbol *sym;
	u64 hits[0];
};

static const char *last_source_name;
static unsigned nr_events;
static unsigned last_line;
static u64 last_off;
static FILE **output_files;
static struct rb_root graph_root;

static inline int64_t cmp_null(void *l, void *r)
{
	if (!l && !r)
		return 0;
	else if (!l)
		return -1;
	else
		return 1;
}

static int64_t map_cmp(struct map *map_l, struct map *map_r)
{
	struct dso *dso_l = map_l ? map_l->dso : NULL;
	struct dso *dso_r = map_r ? map_r->dso : NULL;
	const char *dso_name_l, *dso_name_r;

	if (!dso_l || !dso_r)
		return cmp_null(dso_l, dso_r);

	if (verbose) {
		dso_name_l = dso_l->long_name;
		dso_name_r = dso_r->long_name;
	} else {
		dso_name_l = dso_l->short_name;
		dso_name_r = dso_r->short_name;
	}

	return strcmp(dso_name_l, dso_name_r);
}

static int64_t sym_cmp(struct symbol *sym_l, struct symbol *sym_r)
{
	u64 ip_l, ip_r;

	if (!sym_l || !sym_r)
		return cmp_null(sym_l, sym_r);

	if (sym_l == sym_r)
		return 0;

	ip_l = sym_l->start;
	ip_r = sym_r->start;

	return (int64_t)(ip_r - ip_l);
}

static inline int64_t map_sym_cmp(struct map *map_l, struct symbol *sym_l, 
				  struct map *map_r, struct symbol *sym_r)
{
	int64_t cmp = map_cmp(map_l, map_r);

	if (!cmp)
		return sym_cmp(sym_l, sym_r);
	else
		return cmp;
}

static struct graph_node *add_graph_node(struct map *map, struct symbol *sym)
{
	struct rb_node **rb_node = &(&graph_root)->rb_node, *parent = NULL;
	struct graph_node *node;
	int64_t cmp;

	while (*rb_node) {
		parent = *rb_node;
		node = rb_entry(parent, struct graph_node, rb_node);
		cmp = map_sym_cmp(map, sym, node->map, node->sym);

		if (cmp < 0)
			rb_node = &(*rb_node)->rb_left;
		else if (cmp > 0)
			rb_node = &(*rb_node)->rb_right;
		else {
			if (map != node->map)
				node->map = map;

			return node;
		}
	}

	node = zalloc(sizeof(*node) + nr_events * sizeof(node->stats[0]));
	if (node) {
		node->map = map;
		node->sym = sym;
		node->filename = "";
		node->callees = RB_ROOT;

		if (map)
			map->referenced = true;

		rb_link_node(&node->rb_node, parent, rb_node);
		rb_insert_color(&node->rb_node, &graph_root);
	}

	return node;
}

static struct graph_node *get_graph_node(struct map *map, struct symbol *sym)
{
	struct rb_node *rb_node = (&graph_root)->rb_node;
	struct graph_node *node;
	int64_t cmp;

	while (rb_node) {
		node = rb_entry(rb_node, struct graph_node, rb_node);
		cmp = map_sym_cmp(map, sym, node->map, node->sym);

		if (cmp < 0)
			rb_node = rb_node->rb_left;
		else if (cmp > 0)
			rb_node = rb_node->rb_right;
		else
			return node;
	}

	return NULL;
}

static int graph_node__add_callee(struct graph_node *caller, struct map *map,
				  struct symbol *sym, int idx)
{
	struct rb_node **rb_node = &caller->callees.rb_node, *parent = NULL;
	struct callee *callee;
	int64_t cmp;

	while (*rb_node) {
		parent = *rb_node;
		callee = rb_entry(parent, struct callee, rb_node);
		cmp = map_sym_cmp(map, sym, callee->map, callee->sym);

		if (cmp < 0)
			rb_node = &(*rb_node)->rb_left;
		else if (cmp > 0)
			rb_node = &(*rb_node)->rb_right;
		else{
			callee->hits[idx]++;
			caller->stats[idx].has_callees = true;

			if (map != callee->map)
				callee->map = map;

			return 0;
		}
	}

	callee = zalloc(sizeof(*callee) + nr_events * sizeof(callee->hits[0]));
	if (callee) {
		callee->map = map;
		callee->sym = sym;
		callee->hits[idx] = 1;
		caller->stats[idx].has_callees = true;

		if (map)
			map->referenced = true;

		rb_link_node(&callee->rb_node, parent, rb_node);
		rb_insert_color(&callee->rb_node, &caller->callees);

		return 0;
	} else
		return -ENOMEM;
}

static int add_callchain_to_callgraph(int idx)
{
	struct callchain_cursor_node *caller, *callee;
	struct graph_node *node;
	int err;

	callchain_cursor_commit(&callchain_cursor);
	callee = callchain_cursor_current(&callchain_cursor);

	if (!callee)
		return 0;

	while (true) {
		callchain_cursor_advance(&callchain_cursor);
		caller = callchain_cursor_current(&callchain_cursor);

		if (!caller)
			break;

		node = add_graph_node(caller->map, caller->sym);
		if (!node)
			return -ENOMEM;

		err = graph_node__add_callee(node, callee->map, callee->sym, idx);
		if (err)
			return err;

		callee = caller;
	}

	return 0;
}

static int accumulate_sample(struct perf_evsel *evsel, struct perf_sample *sample,
			     struct addr_location *al, struct machine *machine)
{
	struct symbol *parent = NULL;
	struct graph_node *node;
	int err;

	if (sample->callchain) {
		err = machine__resolve_callchain(machine, evsel, al->thread,
						 sample, &parent);

		if (err)
			return err;
	}

	node = add_graph_node(al->map, al->sym);
	if (!node)
		return -ENOMEM;

	err = add_callchain_to_callgraph(evsel->idx);
	if (err)
		return err;

	node->stats[evsel->idx].hits++;

	if (node->sym != NULL) {
		struct annotation *notes = symbol__annotation(node->sym);
		if (notes->src == NULL && symbol__alloc_hist(node->sym) < 0)
			return -ENOMEM;

		err = symbol__inc_addr_samples(node->sym, node->map, evsel->idx,
					       al->addr);
		if (err)
			return err;
	}

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
	int err;

	if (perf_event__preprocess_sample(event, machine, &al, sample,
					  symbol__annotate_init) < 0) {
		pr_warning("problem processing %d event, skipping it.\n",
			   event->header.type);
		return -1;
	}

	if (cnv->cpu_list && !test_bit(sample->cpu, cnv->cpu_bitmap))
		return 0;

	if (!al.filtered) {
		err = accumulate_sample(evsel, sample, &al, machine);
		if (err) {
			pr_warning("problem incrementing symbol count, skipping event\n");
			return err;
		}
	}

	return 0;
}

static inline void print_header(const char *evname, int idx)
{
	fprintf(output_files[idx], "positions: instr line\nevents: %s\n", evname);
}

static void print_function_header(struct graph_node *node, u64 offset, int idx)
{
	FILE *output = output_files[idx];
	const char *filename;
	struct map *map = node->map;
	struct symbol *sym = node->sym;
	struct annotation *notes = symbol__annotation(sym);
	u64 function_start = map__rip_2objdump(map, sym->start);
	u64 address = function_start + offset;
	int ret;

	filename = "";
	addr2line(function_start, &filename, &last_line);

	/* Cache filename to speedup the callgraph generation */
	node->filename = strdup(filename);

	fprintf(output, "ob=%s\n", map->dso->long_name);
	fprintf(output, "fl=%s\n", filename);
	fprintf(output, "fn=%s\n", sym->name);
	fprintf(output, "0 0\n");

	ret = addr2line(address, &last_source_name, &last_line);
	if (ret && strcmp(filename, last_source_name))
		fprintf(output, "fl=%s\n", last_source_name);

	fprintf(output, "%#" PRIx64 " %u %" PRIu64 "\n", address, last_line,
		annotation__histogram(notes, idx)->addr[offset]);

	last_off = offset;
}

static inline bool event_has_samples(struct annotation *notes, u64 offset, int idx)
{
	return annotation__histogram(notes, idx)->addr[offset];
}

static void print_function_tail(struct graph_node *node, u64 offset, int idx)
{
	int ret;
	unsigned line;
	const char *filename = NULL;
	FILE *output = output_files[idx];
	struct map *map = node->map;
	struct symbol *sym = node->sym;
	struct annotation *notes = symbol__annotation(sym);

	ret = addr2line(map__rip_2objdump(map, sym->start) + offset,
			&filename, &line);
	if (ret && strcmp(filename, last_source_name)) {
		fprintf(output, "fl=%s\n", filename);
		last_source_name = filename;
	}

	if (ret)
		fprintf(output, "+%" PRIu64 " %+d", offset - last_off,
			(int)(line - last_line));
	else{
		fprintf(output, "+%" PRIu64 " 0", offset - last_off);
		line = 0;
	}

	fprintf(output, " %" PRIu64 "\n",
		annotation__histogram(notes, idx)->addr[offset]);

	last_off = offset;
	last_line = line;
}

static void print_function_summary(struct graph_node *node, int idx)
{
	FILE *output = output_files[idx];

	fprintf(output, "ob=%s\n", node->map && node->map->dso ? 
		node->map->dso->long_name : "");

	/* Without the empty fl declaration kcachegrind would apply the last
	 * valid fl declaration in the file*/
	fprintf(output, "fl=\n");
	fprintf(output, "fn=%s\n", node->sym ? node->sym->name : "");
	fprintf(output, "0 0 %" PRIu64, node->stats[idx].hits);
	fprintf(output, "\n");
}

static void print_function(struct graph_node *node, int idx)
{
	struct annotation *notes;
	struct map *map;
	struct symbol *sym;
	u64 sym_len, i;

	if (!node->stats[idx].hits)
		return;

	map = node->map;
	sym = node->sym;

	if (!map || !sym || addr2line_init(map->dso->long_name)) {
		print_function_summary(node, idx);
		return;
	}

	notes = symbol__annotation(sym);
	sym_len = sym->end - sym->start;

	for (i = 0; i < sym_len; i++) {
		if (event_has_samples(notes, i, idx)) {
			print_function_header(node, i, idx);
			break;
		}
	}

	for (++i; i < sym_len; i++) {
		if (event_has_samples(notes, i, idx))
			print_function_tail(node, i, idx);
	}
}

static void print_functions(void){
	struct rb_node *rb_node;
	struct graph_node *node;
	u64 i = 0;

	for (rb_node = rb_first(&graph_root); rb_node; rb_node = rb_next(rb_node)) {
		node = rb_entry(rb_node, struct graph_node, rb_node);

		for (i = 0; i < nr_events; i++)
			print_function(node, i);
	}
}

static void print_callee(struct callee *callee, int idx)
{
	FILE *output = output_files[idx];
	struct graph_node *callee_node;

	if (!callee->hits[idx])
		return;

	if (callee->sym) {
		callee_node = get_graph_node(callee->map, callee->sym);
		fprintf(output, "cob=%s\ncfl=%s\ncfn=%s\n",
			callee->map->dso->long_name, callee_node->filename,
			callee->sym->name);
	} else
		fprintf(output, "cob=%s\ncfl=\ncfn=\n", callee->map ?
			callee->map->dso->long_name : "");

	fprintf(output, "calls=%" PRIu64 "\n0 0 %" PRIu64 "\n",
		callee->hits[idx], callee->hits[idx]);

}

static void print_caller(struct graph_node *node, int idx)
{
	FILE *output = output_files[idx];
	struct callee *callee;
	struct rb_node *rb_node;

	if (!node->stats[idx].has_callees)
		return;

	if (node->sym)
		fprintf(output, "ob=%s\nfl=%s\nfn=%s\n",
			node->map->dso->long_name, node->filename, node->sym->name);
	else
		fprintf(output, "ob=%s\nfl=\nfn=\n",
			node->map ? node->map->dso->long_name : "");

	for (rb_node = rb_first(&node->callees); rb_node; rb_node = rb_next(rb_node)) {
		callee = rb_entry(rb_node, struct callee, rb_node);
		print_callee(callee, idx);
	}
}

static void print_calls(void)
{
	struct rb_node *rb_node;
	struct graph_node *node;
	u64 i = 0;

	for (rb_node = rb_first(&graph_root); rb_node; rb_node = rb_next(rb_node)) {
		node = rb_entry(rb_node, struct graph_node, rb_node);

		for (i = 0; i < nr_events; i++)
			print_caller(node, i);
	}
}

static int __cmd_convert(struct perf_convert *cnv)
{
	int ret;
	unsigned i = 0;
	struct perf_session *session;
	struct perf_evsel *pos;
	char output_filename[100];

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

	output_files = malloc(sizeof(*output_files)*nr_events);
	list_for_each_entry(pos, &session->evlist->entries, node) {
		const char *evname = perf_evsel__name(pos);

		snprintf(output_filename, sizeof(output_filename), "%s%s",
			 cnv->output_prefix, evname);
		output_files[i] = fopen(output_filename, "w");

		if (!output_files[i]) {
			fprintf(stderr, "Cannot open %s for output\n",
				output_filename);
			return -1;
		}

		print_header(evname, i++);
	}

	print_functions();
	print_calls();

	for (i = 0; i < nr_events; i++)
		fclose(output_files[i]);

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
		.output_prefix = "callgrind_"
	};
	const struct option options[] = {
	OPT_STRING('i', "input", &convert.input_name, "file",
		    "input file name"),
	OPT_STRING('p', "prefix", &convert.output_prefix, "prefix", "filename "
		   "prefix of the generated callgrind files, default is 'callgrind_'"),
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
	symbol_conf.use_callchain = true;

	if (callchain_register_param(&callchain_param) < 0) {
		fprintf(stderr, "Can't register callchain params\n");
		return -1;
	}

	if (symbol__init() < 0)
		return -1;

	graph_root = RB_ROOT;

	return __cmd_convert(&convert);
}
