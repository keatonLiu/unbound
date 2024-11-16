
#include "config.h"
#include "util/storage/map.h"
#include "util/log.h"

int default_cmp_func_numeric(const void* a, const void* b) {
    return (a > b) - (a < b);
}

int default_cmp_func_str(const void* a, const void* b) {
    return strcmp((const char*)a, (const char*)b);
}

void map_init(struct map *map, int (*cmpf)(const void *, const void *)) {
    map->tree = rbtree_create(cmpf);
}

void* map_insert(const struct map map, void* key, void* data) {
    map_node_type* node = (map_node_type*)calloc(1, sizeof(map_node_type));
    if (!node) {
        log_warn("map_insert->node: memory allocation failed");
        return NULL;
    }
    node->node.key = key;
    node->data = data;
    // find the node in the tree
    rbnode_type* rbnode = rbtree_search(map.tree, key);
    if (rbnode) {
        map_node_type *old_node = (map_node_type*)rbnode;
        old_node->data = data;
        free(node);
        return data;
    }
    rbnode = rbtree_insert(map.tree, &node->node);
    if (!rbnode) {
        log_warn("map_insert: key already present");
        return NULL;
    }
    return data;
}

void* map_get(const struct map map, const void* key) {
    rbnode_type* rbnode = rbtree_search(map.tree, key);
    if (!rbnode) {
        return NULL;
    }
    map_node_type* node = (map_node_type*)rbnode;
    return node->data;
}

void* map_pop(const struct map map, const void* key) {
    rbnode_type* rbnode = rbtree_delete(map.tree, key);
    if (!rbnode) {
        return NULL;
    }
    map_node_type* node = (map_node_type*)rbnode;
    void* data = node->data;
    free(node);
    return data;
}

void map_delete(const struct map map) {
    map_node_type* node;
    
    if (map.tree) {
        struct map_node_type* nodes[map.tree->count];
        int i = 0;
        RBTREE_FOR(node, map_node_type*, map.tree) {
            nodes[i++] = node;
        }
        for (i = 0; i < map.tree->count; i++) {
            free(nodes[i]);
        }
        free(map.tree);
    }
}

int map_equal(const struct map map1, const struct map map2) {
    if (map1.tree->count != map2.tree->count) {
        return 0;
    }
    map_node_type* node1;
    map_node_type* node2;
    RBTREE_FOR(node1, map_node_type*, map1.tree) {
        node2 = (map_node_type*)rbtree_search(map2.tree, node1->node.key);
        if (!node2 || node1->data != node2->data) {
            return 0;
        }
    }
    return 1;
}