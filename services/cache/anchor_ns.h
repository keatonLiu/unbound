#ifndef SERVICES_CACHE_ANCHOR_NS_H
#define SERVICES_CACHE_ANCHOR_NS_H
#include "config.h" // must include to get the correct platform-specific headers
#include "util/storage/set.h"
#include "util/data/msgreply.h"
struct anchor_ns_set;
struct anchor_ns_cache;
struct anchor_ns;

struct anchor_ns
{
    char* name;
    SimpleSet* ips;
};

struct anchor_ns *anchor_ns_create(const char *name);

/**
 * The anchor ns set, stores all NSs for a zone
 */
struct anchor_ns_set
{
    char* zone;
    SimpleSet* nss;
};

struct anchor_ns_set* anchor_ns_set_create();
struct anchor_ns_set* anchor_ns_set_from_rep(const char* zone, const struct reply_info *rep);
int anchor_ns_set_compare(const struct anchor_ns_set *parent, const struct anchor_ns_set *child);

/**
 * The anchor ns cache, stores all anchor ns sets
 */
struct anchor_ns_cache
{
    SimpleSet* zones; // set of zones
};

struct anchor_ns_cache* anchor_ns_cache_create();
struct anchor_ns_set* anchor_ns_cache_get(struct anchor_ns_cache* cache, const char* zone);
int anchor_ns_cache_set(const struct anchor_ns_cache* cache, const struct anchor_ns_set* set);

// LOGGING FUNCTIONS
void anchor_ns_set_log(const struct anchor_ns_set *cache);
void anchor_ns_log(const struct anchor_ns *ns);

// HASH FUNCTIONS
uint64_t anchor_ns_set_hash(const char* key);
uint64_t anchor_ns_hash(const char *key);

#endif // SERVICES_CACHE_ANCHOR_NS_H