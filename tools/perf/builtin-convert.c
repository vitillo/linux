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
#include "util/cgcnv.h"

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

	if (!al.filtered && cg_cnv_sample(evsel, sample, &al, machine,
	      				  &cnv->graph_root)) {
		pr_warning("problem incrementing symbol count, skipping event\n");
		return -1;
	}

	return 0;
}

static void hists__find_annotations(struct hists *self, int evidx,
				    struct perf_convert *cnv)
{
	struct rb_node *nd = rb_first(&self->entries);
	int key = K_RIGHT;

	while (nd) {
		struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);
		struct annotation *notes;

		if (he->ms.sym == NULL || he->ms.map->dso->annotate_warned) {
			cg_cnv_unresolved(cnv->output_file, evidx, he);
			goto find_next;
		}

		notes = symbol__annotation(he->ms.sym);

		if (notes->src == NULL) {
find_next:
			if (key == K_LEFT)
				nd = rb_prev(nd);
			else
				nd = rb_next(nd);
			continue;
		}

		cg_cnv_symbol(cnv->output_file, he->ms.sym, he->ms.map);

		free(notes->src);
		notes->src = NULL;
	}
}

static int __cmd_convert(struct perf_convert *cnv)
{
	int ret;
	struct perf_session *session;
	struct perf_evsel *pos;
	u64 total_nr_samples = 0;

	session = perf_session__new(cnv->input_name, O_RDONLY,
				    cnv->force, false, &cnv->tool);
	if (session == NULL)
		return -ENOMEM;
	
	cg_set_nr_events(session->evlist->nr_entries);
	
	if (cnv->cpu_list) {
		ret = perf_session__cpu_bitmap(session, cnv->cpu_list,
					       cnv->cpu_bitmap);
		if (ret)
			goto out_delete;
	}

	ret = perf_session__process_events(session, &cnv->tool);
	if (ret)
		goto out_delete;

	ret = cg_cnv_header(cnv->output_file, session);
	if (ret)
		goto out_delete;

	list_for_each_entry(pos, &session->evlist->entries, node) {
		struct hists *hists = &pos->hists;
		u32 nr_samples = hists->stats.nr_events[PERF_RECORD_SAMPLE];

		if (nr_samples > 0) {
			total_nr_samples += nr_samples;
			hists__collapse_resort(hists);
			hists__output_resort(hists);
			hists__find_annotations(hists, pos->idx, cnv);
		}

		cg_cnv_callgraph(cnv->output_file, cnv->graph_root.rb_node);
	}

	if (total_nr_samples == 0) {
		ui__error("The %s file has no samples!\n", session->filename);
		goto out_delete;
	}

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
		.graph_root = RB_ROOT,
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
	symbol_conf.use_callchain = true;

	callchain_param.mode = CHAIN_GRAPH_REL;
	callchain_param.order = ORDER_CALLEE;

	//TODO: if I remove the following 3 lines perf segfaults...
	if (callchain_register_param(&callchain_param) < 0) {
	 	fprintf(stderr, "Can't register callchain params\n");
		return -1;
	}

	convert.output_file = fopen(output_filename, "w");
	if (!convert.output_file) {
		fprintf(stderr, "Cannot open %s for output\n", output_filename);
		return -1;
	}

	if (symbol__init() < 0)
		return -1;

	if (setup_sorting() < 0)
		usage_with_options(convert_usage, options);

	return __cmd_convert(&convert);
}
