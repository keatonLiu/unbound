#ifndef UTIL_STORAGE_MAP_H
#define UTIL_STORAGE_MAP_H

/**
 * \file
 * Implementation of a map data structure.
 * Wraps around a red-black tree.
 */

#include "util/rbtree.h"

struct map {
    struct rbtree_type* tree;
};

typedef struct map_node_type {
    rbnode_type node;
    void* data;
} map_node_type;

void map_init(struct map *map, int (*cmpf)(const void *, const void *));

void* map_insert(const struct map map, void* key, void* data);

void* map_get(const struct map map, const void* key);

void* map_pop(const struct map map, const void* key);

void map_delete(const struct map map);

// COMPARE FUNCS
int default_cmp_func_numeric(const void* a, const void* b);
int default_cmp_func_str(const void* a, const void* b);

#endif /* UTIL_STORAGE_MAP_H */