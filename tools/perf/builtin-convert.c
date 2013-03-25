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
	char const *output_name;
	bool	   force;
	const char *cpu_list;
	DECLARE_BITMAP(cpu_bitmap, MAX_NR_CPUS);
};

struct callee_node {
  struct rb_node rb_node;
  struct map *map;
  struct symbol *sym;
  u64 address;
  u64 hits[0];
};

struct stats{
	u64 hits;
	bool has_callees;
};

struct graph_node {
  u64 address;
  const char *filename;
  struct rb_node rb_node;
  struct map *map;
  struct symbol *sym;
  struct rb_root callees;
  struct stats stats[0];
};

static const char *last_source_name;
static unsigned last_line;
static u64 last_off;
static unsigned nr_events;
static FILE **output_files;
static struct rb_root graph_root;

static struct graph_node *add_graph_node(struct map *map,
					 struct symbol *sym, u64 ip)
{
	struct rb_node **rb_node = &(&graph_root)->rb_node, *parent = NULL;
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

	node = calloc(1, sizeof(*node) + nr_events * sizeof(node->stats[0]));
	node->map = map;
	node->sym = sym;
	node->address = address;
	node->filename = "";
	node->callees = RB_ROOT;

	rb_link_node(&node->rb_node, parent, rb_node);
	rb_insert_color(&node->rb_node, &graph_root);

	return node;
}

static struct graph_node *get_graph_node(u64 address)
{
	struct rb_node *rb_node = (&graph_root)->rb_node;
	struct graph_node *node;

	while (rb_node){
		node = rb_entry(rb_node, struct graph_node, rb_node);

		if (address < node->address)
		 	rb_node = rb_node->rb_left;
		else if (address > node->address)
		  	rb_node = rb_node->rb_right;
		else
		  	return node;
	}

	return NULL;
}

static void graph_node__add_callee(struct graph_node *caller, struct map *map,
    				   struct symbol *sym, u64 ip, int idx)
{
	struct rb_node **rb_node = &caller->callees.rb_node, *parent = NULL;
	struct  callee_node *callee;
	u64 address = sym ? sym->start : map ? map->start : ip;

	while (*rb_node){
	  	parent = *rb_node;
		callee = rb_entry(parent, struct callee_node, rb_node);

		if (address < callee->address)
		 	rb_node = &(*rb_node)->rb_left;
		else if (address > callee->address)
		  	rb_node = &(*rb_node)->rb_right;
		else{
			callee->hits[idx]++;
			caller->stats[idx].has_callees = true;
			return;
		}
	}

	callee = calloc(1, sizeof(*callee) + nr_events *
			sizeof(callee->hits[0]));
	callee->map = map;
	callee->sym = sym;
	callee->address = address;
	callee->hits[idx] = 1;
	caller->stats[idx].has_callees = true;

	rb_link_node(&callee->rb_node, parent, rb_node);
	rb_insert_color(&callee->rb_node, &caller->callees);
}

static void add_callchain_to_callgraph(int idx)
{
	struct callchain_cursor_node *caller, *callee;
	struct graph_node *node;

	callchain_cursor_commit(&callchain_cursor);
	callee = callchain_cursor_current(&callchain_cursor);

	if(!callee)
	  return;

	while (true) {
	  	callchain_cursor_advance(&callchain_cursor);
		caller = callchain_cursor_current(&callchain_cursor);

		if (!caller)
		  break;

		node = add_graph_node(caller->map, caller->sym, caller->ip);
		graph_node__add_callee(node, callee->map, callee->sym,
		    		       callee->ip, idx);

		callee = caller;
	}
}

static int accumulate_sample(struct perf_evsel *evsel, struct perf_sample *sample, struct addr_location *al, struct machine *machine)
{
	struct symbol *parent = NULL;
	struct graph_node *node;
	int err = 0;

	if (sample->callchain) {
		err = machine__resolve_callchain(machine, evsel, al->thread,
						 sample, &parent);

		if (err)
			return err;
	}

	node = add_graph_node(al->map, al->sym, al->addr);
	add_callchain_to_callgraph(evsel->idx);
	node->stats[evsel->idx].hits++;

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

	if (!al.filtered && accumulate_sample(evsel, sample, &al, machine)) {
		pr_warning("problem incrementing symbol count, skipping event\n");
		return -1;
	}

	return 0;
}

static inline void print_header(const char *evname, int idx)
{
	fprintf(output_files[idx], "positions: instr line\nevents: %s\n", evname);
}

static void print_function_header(struct graph_node *node, struct symbol *sym, struct map *map, struct annotation *notes, u64 offset, int idx)
{
	int ret;
	u64 function_start = map__rip_2objdump(map, sym->start);
	u64 address = function_start + offset;
	const char *filename;
	FILE *output = output_files[idx];

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

	fprintf(output, "%#" PRIx64 " %u", address, last_line);
	fprintf(output, " %" PRIu64, annotation__histogram(notes, idx)->addr[offset]);

	fprintf(output, "\n");
	last_off = offset;
}

static inline bool events_have_samples(struct annotation *notes, u64 offset, int idx)
{
 	return annotation__histogram(notes, idx)->addr[offset];
}

static void print_function_tail(struct symbol *sym, struct map *map, struct annotation *notes, u64 offset, int idx)
{
	int ret;
	unsigned line;
	const char *filename = NULL;
	FILE *output = output_files[idx];

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

	fprintf(output, " %" PRIu64, annotation__histogram(notes, idx)->addr[offset]);

	fprintf(output, "\n");
	last_off = offset;
	last_line = line;
}

static void print_function_summary(struct graph_node *node, int idx)
{
  	FILE *output = output_files[idx];

	fprintf(output, "ob=%s\n", node->map ? node->map->dso->long_name : "");
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
	
	if(!node->stats[idx].hits)
	  	return;

	map = node->map;
	sym = node->sym;

	if(!map || !sym || addr2line_init(map->dso->long_name)){
		print_function_summary(node, idx);
		return;
	}
	
	notes = symbol__annotation(sym);
	sym_len = sym->end - sym->start;

	for (i = 0; i < sym_len; i++) {
		if (events_have_samples(notes, i, idx)) {
			print_function_header(node, sym, map, notes, i, idx);
			break;
		}
	}

	for (++i; i < sym_len; i++) {
		if (events_have_samples(notes, i, idx))
			print_function_tail(sym, map, notes, i, idx);
	}
}

static void print_functions(void){
  	struct rb_node *rb_node;
	struct graph_node *node;
	u64 i = 0;

	for(rb_node = rb_first(&graph_root); rb_node; rb_node = rb_next(rb_node)){
		node = rb_entry(rb_node, struct graph_node, rb_node);

		for(i = 0; i < nr_events; i++)
			print_function(node, i);
	}
}

static void print_callee(struct callee_node *callee, int idx)
{
	FILE *output = output_files[idx];
  	struct graph_node *callee_node;

	if(!callee->hits[idx])
		return;

	if(callee->sym){
		fprintf(output, "cob=%s\n", callee->map->dso->long_name);
		callee_node = get_graph_node(callee->address);
		fprintf(output, "cfl=%s\n", callee_node->filename);
		fprintf(output, "cfn=%s\n", callee->sym->name);
	}else{
		fprintf(output, "cob=%s\n", callee->map ? 
			callee->map->dso->long_name : "");
		fprintf(output, "cfl=\n");
		fprintf(output, "cfn=\n");
	}

	fprintf(output, "calls=%" PRIu64 "\n", callee->hits[idx]);
	fprintf(output, "0 0 %" PRIu64 " \n", callee->hits[idx]);

}

static void print_caller(struct graph_node *node, int idx)
{
	FILE *output = output_files[idx];
	struct callee_node *callee;
	struct rb_node *rb_node;

	if(!node->stats[idx].has_callees)
		return;

	if (node->sym) {
		fprintf(output, "ob=%s\n", node->map->dso->long_name);
		fprintf(output, "fl=%s\n", node->filename);
		fprintf(output, "fn=%s\n", node->sym->name);
	}else{
		fprintf(output, "ob=%s\n", node->map ? node->map->dso->long_name
						     : "");
		fprintf(output, "fl=\n");
		fprintf(output, "fn=\n");
	}

	for(rb_node = rb_first(&node->callees); rb_node; rb_node = rb_next(rb_node)){
		callee = rb_entry(rb_node, struct callee_node, rb_node);
		print_callee(callee, idx);
	}
}

static void print_calls(void)
{
	struct rb_node *rb_node;
	struct graph_node *node;
	u64 i = 0;

	for(rb_node = rb_first(&graph_root); rb_node; rb_node = rb_next(rb_node)){
		node = rb_entry(rb_node, struct graph_node, rb_node);

		for(i = 0; i < nr_events; i++)
			print_caller(node, i);
	}
}

static int __cmd_convert(struct perf_convert *cnv)
{
	int ret, i = 0;
	struct perf_session *session;
	struct perf_evsel *pos;

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
		output_files[i] = fopen(evname, "w");

      		if (!output_files[i]){
	      		fprintf(stderr, "Cannot open %s for output\n", evname);
	      		return -1;
		}

		print_header(evname, i++);
	}

	print_functions();
	print_calls();

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
		.output_name = "callgrind"
	};
	const struct option options[] = {
	OPT_STRING('i', "input", &convert.input_name, "file",
		    "input file name"),
	OPT_STRING('o', "output", &convert.output_name, "output", "output filename prefix, default is callgrind"),
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
