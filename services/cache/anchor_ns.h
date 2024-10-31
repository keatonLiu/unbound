#ifndef SERVICES_CACHE_ANCHOR_NS_H
#define SERVICES_CACHE_ANCHOR_NS_H
#include "util/storage/slabhash.h"
#include "util/storage/set.h"
/**
 * The anchor ns cache, stores all NSs for a zone
 */
struct anchor_ns_cache
{
    const char* zone;
    SimpleSet* nss;
};

struct anchor_ns_cache* anchor_ns_cache_create();

struct anchor_ns
{
    const char* name;
    const char* ip;
};

struct anchor_ns *anchor_ns_create(const char *name, const char *ip);
static uint64_t anchor_ns_hash(const char *key);

#endif // SERVICES_CACHE_ANCHOR_NS_H