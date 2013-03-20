#include "cgcnv.h"
#include "a2l.h"
#include "parse-events.h"
#include "symbol.h"
#include "map.h"
#include "util.h"
#include "annotate.h"

#include <linux/list.h>
#include <linux/rbtree.h>

static const char *last_source_name;
static unsigned last_line;
static u64 last_off;
static u64 nr_events;

void cg_set_nr_events(u64 nr){
	nr_events = nr;
}

int cg_cnv_header(FILE *output, struct perf_session *session)
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

static struct graph_node *add_graph_node(struct rb_root *root, struct map *map,
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
	node->filename = "";
	INIT_LIST_HEAD(&node->callees);

	rb_link_node(&node->rb_node, parent, rb_node);
	rb_insert_color(&node->rb_node, root);

	return node;
}

static struct graph_node *get_graph_node(struct rb_root *root, u64 address)
{
	struct rb_node *rb_node = root->rb_node;
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

static void graph_node__add_callee(struct graph_node *node, struct map *map,
    				   struct symbol *sym, u64 ip, int idx){
  	struct callee_list *callee;
	u64 address = sym ? sym->start : map ? map->start : ip;

	list_for_each_entry(callee, &node->callees, list)
	 	if (callee->address == address)
		  	goto incr;

	callee = calloc(1, sizeof(*callee) + nr_events *
			sizeof(callee->hits[0]));
	callee->map = map;
	callee->sym = sym;
	callee->address = address;
	list_add(&callee->list, &node->callees);

incr:
	callee->hits[idx]++;
}

static void add_callchain_to_callgraph(struct perf_evsel *evsel,
    				       struct rb_root *graph_root){
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

		node = add_graph_node(graph_root, caller->map, caller->sym,
		    		      caller->ip);
		graph_node__add_callee(node, callee->map, callee->sym,
		    		       callee->ip, evsel->idx);

		callee = caller;
	}
}

int cg_cnv_sample(struct perf_evsel *evsel, struct perf_sample *sample,
		  struct addr_location *al, struct machine *machine,
		  struct rb_root *graph_root)
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

	node = add_graph_node(graph_root, al->map, al->sym, al->addr);
	add_callchain_to_callgraph(evsel, graph_root);
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

static void cg_sym_header_printf(FILE *output, struct symbol *sym,
				 struct map *map, struct annotation *notes,
				 u64 offset)
{
	int idx, ret_callee;
	u64 address = map__rip_2objdump(map, sym->start) + offset;
	ret_callee = addr2line(address, &last_source_name, &last_line);

	if (ret_callee && last_line)
		fprintf(output, "fl=%s\n", last_source_name);

	fprintf(output, "%#" PRIx64 " %u", address, last_line);
	for (idx = 0; idx < notes->src->nr_histograms; idx++)
		fprintf(output, " %" PRIu64,
			annotation__histogram(notes, idx)->addr[offset]);

	fprintf(output, "\n");
	last_off = offset;
}

static void cg_sym_events_printf(FILE *output, struct symbol *sym,
				 struct map *map, struct annotation *notes,
				 u64 offset)
{
	int ret, idx;
	unsigned line;
	const char *filename;

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

static inline bool cg_check_events(struct annotation *notes, u64 offset)
{
	int idx;

	for (idx = 0; idx < notes->src->nr_histograms; idx++)
		if (annotation__histogram(notes, idx)->addr[offset])
			return true;

	return false;
}

static void cg_sym_total_printf(FILE *output, struct annotation *notes)
{
	int idx;

	fprintf(output, "0 0");
	for (idx = 0; idx < notes->src->nr_histograms; idx++) {
		u64 cnt = annotation__histogram(notes, idx)->sum;
		fprintf(output, " %" PRIu64, cnt);
	}
	fprintf(output, "\n");
}

static void cg_cnv_unresolved(FILE *output, struct graph_node *node)
{
	unsigned idx;

	fprintf(output, "ob=%s\n", node->map ? node->map->dso->long_name : "");
	fprintf(output, "fl=\n");
	fprintf(output, "fn=\n");

	fprintf(output, "0 0");
	for (idx = 0; idx < nr_events; idx++)
		fprintf(output, " %" PRIu64, node->hits[idx]);
	fprintf(output, "\n");
}

static int cg_cnv_symbol(FILE *output, struct graph_node *node)
{
	struct annotation *notes;
	struct map *map = node->map;
	struct symbol *sym = node->sym;
	const char *dso_name, *filename = "";
	u64 sym_len, i;
	unsigned line;
	
	if(!map || !sym){
		cg_cnv_unresolved(output, node);
		return -1;
	}
	
	dso_name = map->dso->long_name;
	notes = symbol__annotation(sym);
	sym_len = sym->end - sym->start;

	if (addr2line_init(map->dso->long_name)) {
		if(!notes->src) // No samples
			return -1;

		fprintf(output, "ob=%s\n", dso_name);
	  	fprintf(output, "fl=\n");
		fprintf(output, "fn=%s\n", sym->name);
		cg_sym_total_printf(output, notes);
		return -EINVAL;
	}

	addr2line(map__rip_2objdump(map, sym->start), &filename, &line);
	
	/* Cache filename to speedup the callgraph generation */
	node->filename = strdup(filename);
		
	if(!notes->src)
		return -1;
	
	/* KCachegrind wants the fl declaration before the fn one */
	fprintf(output, "ob=%s\n", dso_name);
	fprintf(output, "fl=%s\n", filename);
	fprintf(output, "fn=%s\n", sym->name);

	/* Cache filename to speedup the callgraph generation */
	node->filename = strdup(filename ? filename : "");

	for (i = 0; i < sym_len; i++) {
		if (cg_check_events(notes, i)) {
			cg_sym_header_printf(output, sym, map, notes, i);
			break;
		}
	}

	for (++i; i < sym_len; i++) {
		if (cg_check_events(notes, i))
			cg_sym_events_printf(output, sym, map, notes, i);
	}

	return 0;
}

static void scan_callgraph(FILE *output, struct rb_node *rb_node){
	struct graph_node *node;

	if(!rb_node)
		return;

	node = rb_entry(rb_node, struct graph_node, rb_node);
	scan_callgraph(output, rb_node->rb_left);
	cg_cnv_symbol(output, node);
	scan_callgraph(output, rb_node->rb_right);
}

static void dump_callgraph(FILE *output, struct rb_root *graph_root,
			   struct rb_node *rb_node){
	struct graph_node *node, *callee_node;
	struct callee_list *callee;
	unsigned i;

  	if(!rb_node)
	  return;

	node = rb_entry(rb_node, struct graph_node, rb_node);

	if (node->sym) {
		fprintf(output, "ob=%s\n", node->map->dso->long_name);
		fprintf(output, "fl=%s\n", node->filename);
		fprintf(output, "fn=%s\n", node->sym->name);
	}else{
		fprintf(output, "ob=%s\n", node->map ? node->map->dso->long_name : "");
		fprintf(output, "fl=\n");
		fprintf(output, "fn=\n");
	}

	list_for_each_entry(callee, &node->callees, list){
		if(callee->sym){
			fprintf(output, "cob=%s\n", callee->map->dso->long_name);
			callee_node = get_graph_node(graph_root, callee->address);
			fprintf(output, "cfl=%s\n", callee_node->filename);
			fprintf(output, "cfn=%s\n", callee->sym->name);
		}else{
			fprintf(output, "cob=%s\n", callee->map ? 
				callee->map->dso->long_name : "");
			fprintf(output, "cfl=\n");
			fprintf(output, "cfn=\n");
		
		}

		fprintf(output, "calls=");
		for (i = 0; i < nr_events; i++)
			fprintf(output, "%" PRIu64 " ", callee->hits[i]);

		fprintf(output, "\n0 0 ");
		for (i = 0; i < nr_events; i++)
			fprintf(output, "%" PRIu64 " ", callee->hits[i]);

		fprintf(output, "\n");
	}

	dump_callgraph(output, graph_root, rb_node->rb_left);
	dump_callgraph(output, graph_root, rb_node->rb_right);
}

void cg_cnv_callgraph(FILE *output, struct rb_root *graph_root, struct rb_node *rb_node){
	scan_callgraph(output, rb_node);
	dump_callgraph(output, graph_root, rb_node);
}
