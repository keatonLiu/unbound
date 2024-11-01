#ifndef SERVICES_CACHE_ANCHOR_NS_H
#define SERVICES_CACHE_ANCHOR_NS_H
#include "util/storage/slabhash.h"
#include "util/storage/set.h"
/**
 * The anchor ns cache, stores all anchor ns sets
 */
struct anchor_ns_cache
{
    SimpleSet* zones;
};

struct anchor_ns_cache* anchor_ns_cache_create();

/**
 * The anchor ns set, stores all NSs for a zone
 */
struct anchor_ns_set
{
    const char* zone;
    SimpleSet* nss;
};

struct anchor_ns_set* anchor_ns_set_create();
struct anchor_ns_set *anchor_ns_set_from_rep(struct reply_info *rep);
int compare_anchor_ns_set(struct anchor_ns_set *parent, struct anchor_ns_set *child);

struct anchor_ns
{
    const char* name;
    SimpleSet* ips;
};

struct anchor_ns *anchor_ns_create(const char *name);

// HASH FUNCTIONS
static uint64_t anchor_ns_hash(const char *key);
static uint64_t anchor_ns_set_hash(const char* key);

#endif // SERVICES_CACHE_ANCHOR_NS_H