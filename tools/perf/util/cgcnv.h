#ifndef CGCNV_H
#define CGCNV_H

#include "evlist.h"
#include "evsel.h"
#include "session.h"

#include <linux/rbtree.h>
#include <linux/list.h>

#include <stdio.h>

struct callee_list {
  struct list_head list;
  struct map *map;
  struct symbol *sym;
  u64 address;
  u64 hits[0];
};

struct graph_node {
  u64 address;
  const char *filename;
  struct rb_node rb_node;
  struct map *map;
  struct symbol *sym;
  struct list_head callees;
  u64 hits[0];
};

void cg_set_nr_events(u64 nr_events);
int cg_cnv_header(FILE *output, struct perf_session *session);
int cg_cnv_sample(struct perf_evsel *evsel, struct perf_sample *sample,
		  struct addr_location *al, struct machine *machine,
		  struct rb_root *graph_root);
//void cg_cnv_unresolved(FILE *output, int evidx, struct hist_entry *he);
//int cg_cnv_symbol(FILE *output, struct symbol *sym, struct map *map, struct graph_node *node);
void cg_cnv_callgraph(FILE *output, struct rb_root *graph_root, struct rb_node *rb_node);

#endif

