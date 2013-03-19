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
		const char *evname = NULL;
		struct hists *hists = &pos->hists;
		u32 nr_samples = hists->stats.nr_events[PERF_RECORD_SAMPLE];

		if (nr_samples > 0) {
			evname = perf_evsel__name(pos);
			fprintf(output, " %s", evname);
		}
	}
	fprintf(output, "\n");

	return 0;
}

static struct graph_node *get_graph_node(struct rb_root *root, struct map *map,
    					 struct symbol *sym, u64 ip)
{
	struct rb_node **rb_node = &root->rb_node, *parent = NULL;
	struct graph_node *node;
	u64 address = sym ? sym->start : ip;

	while (*rb_node){
	  	parent = *rb_node;
		node = rb_entry(parent, struct graph_node, rb_node);

		if (address < node->address)
		 	rb_node = &(*rb_node)->rb_left;
		else if (address > node->address)
		  	rb_node = &(*rb_node)->rb_right;
		else{
		  	return node;
		}
	}

	node = calloc(sizeof(struct graph_node) + nr_events*sizeof(u64), 1);
	node->map = map;
	node->sym = sym;
	node->address = address;
	INIT_LIST_HEAD(&node->callees.list);

	rb_link_node(&node->rb_node, parent, rb_node);
	rb_insert_color(&node->rb_node, root);

	return node;
}

static void graph_node__add_callee(struct graph_node *node, struct map *map,
    				   struct symbol *sym, u64 ip, int idx){
  	struct callee_list *callee;
	u64 address = sym ? sym->start : ip;

	list_for_each_entry(callee, &node->callees.list, list)
	 	if (callee->address == address)
		  	goto incr;

	callee = calloc(sizeof(struct callee_list) + nr_events*sizeof(u64), 1);
	callee->map = map;
	callee->sym = sym;
	callee->address = address;
	list_add(&callee->list, &node->callees.list);

incr:
	callee->hits[idx]++;
}

int cg_cnv_sample(struct perf_evsel *evsel, struct perf_sample *sample,
		  struct addr_location *al, struct machine *machine,
		  struct rb_root *graph_root)
{
  	struct symbol *parent = NULL;
	struct hist_entry *he;
	struct callchain_cursor_node *caller, *callee;
	struct graph_node *node;
	int ret = 0;

	if (sample->callchain) {
	  ret = machine__resolve_callchain(machine, evsel, al->thread, sample, 
	      				   &parent);
	}

	he = __hists__add_entry(&evsel->hists, al, NULL, 1);
	if (he == NULL)
		return -ENOMEM;

	callchain_cursor_commit(&callchain_cursor);
	callee = callchain_cursor_current(&callchain_cursor);

	while (true) {
	  	callchain_cursor_advance(&callchain_cursor);
		caller = callchain_cursor_current(&callchain_cursor);

		if (!caller)
		  break;

		/*if (caller->sym && callee->sym) {*/
		  	//printf("%s -> %s\n", caller->sym->name, callee->sym->name);

		node = get_graph_node(graph_root, caller->map, caller->sym,
		    		      caller->ip);
		graph_node__add_callee(node, callee->map, callee->sym,
		    		       callee->ip, evsel->idx);

		//TODO: Handle other 3 cases
		callee = caller;

		//TODO: To compare two symbols in the hashtable just use the the sym->start, 
		//or the IP address (if sym == NULL). There is no need to compare library names or function names!
	}

	ret = 0;
	if (he->ms.sym != NULL) {
		struct annotation *notes = symbol__annotation(he->ms.sym);
		if (notes->src == NULL && symbol__alloc_hist(he->ms.sym) < 0)
			return -ENOMEM;

		ret = hist_entry__inc_addr_samples(he, evsel->idx, al->addr);
	}

	evsel->hists.stats.total_period += sample->period;
	hists__inc_nr_events(&evsel->hists, PERF_RECORD_SAMPLE);
	return ret;
}

static void cg_sym_header_printf(FILE *output, struct symbol *sym,
				 struct map *map, struct annotation *notes,
				 u64 offset)
{
	int idx, ret, ret_callee, ret_caller = 0;
	u64 address = map__rip_2objdump(map, sym->start) + offset;
	unsigned caller_line;
	const char *caller_name;

	ret_callee = addr2line(address, &last_source_name, &last_line);
	while ((ret = addr2line_inline(&caller_name, &caller_line)))
		ret_caller = ret;

	/* Needed to display correctly the inlining relationship in kcachegrind *
	if (ret_caller && caller_line)
		fprintf(output, "fl=%s\n0 0\n", caller_name);*/

	if (ret_callee && last_line)
		fprintf(output, "fl=%s\n", last_source_name);
	/*else*/
		/*fprintf(output, "fl=\n");*/

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

void cg_cnv_unresolved(FILE *output, int evidx, struct hist_entry *he)
{
	int idx;

	fprintf(output, "ob=%s\n", he->ms.map->dso->long_name);
	fprintf(output, "fn=%#" PRIx64 "\n", he->ip);

	fprintf(output, "0 0");
	for (idx = 0; idx < evidx; idx++)
		fprintf(output, " 0");
	fprintf(output, " %" PRIu32, he->stat.nr_events);
	fprintf(output, "\n");
}

int cg_cnv_symbol(FILE *output, struct symbol *sym, struct map *map)
{
	const char *filename = map->dso->long_name;
	struct annotation *notes = symbol__annotation(sym);
	u64 sym_len = sym->end - sym->start, i;
	unsigned line;

	fprintf(output, "ob=%s\n", filename);

	if (addr2line_init(map->dso->long_name)) {
		fprintf(output, "fn=%s\n", sym->name);
		cg_sym_total_printf(output, notes);
		return -EINVAL;
	}

	if(addr2line(map__rip_2objdump(map, sym->start), &filename, &line)){
		fprintf(output, "fl=%s\n", filename);
	}else
	  	fprintf(output, "fl=\n");

	fprintf(output, "fn=%s\n", sym->name);

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

	addr2line_cleanup();

	return 0;
}

void cg_cnv_callgraph(FILE *output, struct rb_node *rb_node){
	struct graph_node *node;
	struct callee_list *callee;
	const char *filename;
	unsigned i, line;

  	if(!rb_node)
	  return;

	node = rb_entry(rb_node, struct graph_node, rb_node);

	if (node->sym) {
		fprintf(output, "ob=%s\n", node->map->dso->long_name);

	 	if(!addr2line_init(node->map->dso->long_name)){
			addr2line(map__rip_2objdump(node->map, node->sym->start), &filename, &line);
			fprintf(output, "fl=%s\n", filename ? filename : "");
			addr2line_cleanup();
		}else{
			fprintf(output, "fl=\n");
		}

		// Function name needs to be printed out after ob and fl, otherwise kcachegrind 
		// doesn't display the callchains correctly
		fprintf(output, "fn=%s\n", node->sym->name);
	}else{
		fprintf(output, "ob=%s\n", node->map ? node->map->dso->long_name : "");
		fprintf(output, "fl=\n");
		fprintf(output, "fn=%#" PRIx64 "\n", node->address);
	}


	list_for_each_entry(callee, &node->callees.list, list){
		if(callee->sym){
			fprintf(output, "cob=%s\n", callee->map->dso->long_name);
			if (!addr2line_init(callee->map->dso->long_name)){
				addr2line(map__rip_2objdump(callee->map, callee->sym->start),
							    &filename, &line);
				if (filename)
					fprintf(output, "cfl=%s\n", filename);
				else
				  	fprintf(output, "cfl=\n");

				addr2line_cleanup();
			}
			fprintf(output, "cfn=%s\n", callee->sym->name);

		}else{
			fprintf(output, "cob=%s\n", callee->map ? callee->map->dso->long_name : "");
			fprintf(output, "cfl=\n");
			fprintf(output, "cfn=%#" PRIx64 "\n", callee->address);
		
		}

		fprintf(output, "calls=");
		for (i = 0; i < nr_events; i++)
			fprintf(output, "%" PRIu64 " ", callee->hits[i]);

		fprintf(output, "\n0 0 ");
		for (i = 0; i < nr_events; i++)
			fprintf(output, "%" PRIu64 " ", callee->hits[i]);

		fprintf(output, "\n");
	}

	cg_cnv_callgraph(output, rb_node->rb_left);
	cg_cnv_callgraph(output, rb_node->rb_right);
}
