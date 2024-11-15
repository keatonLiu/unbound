#ifndef SERVICES_CACHE_ANCHOR_NS_H
#define SERVICES_CACHE_ANCHOR_NS_H
#include "config.h" // must include to get the correct platform-specific headers
#include "util/storage/map.h"
#include "util/data/msgreply.h"
struct anchor_ns_set;
struct anchor_ns_cache;
struct anchor_ns;

/**
 * The anchor ns cache, stores all anchor ns sets
 */
struct anchor_ns_cache
{
    struct map zones; // zone -> ns_map
};

struct anchor_ns_cache* anchor_ns_cache_create();
struct anchor_ns_set* anchor_ns_cache_get(const struct anchor_ns_cache* cache, const char* zone);
struct anchor_ns_set* anchor_ns_cache_set(const struct anchor_ns_cache* cache, struct anchor_ns_set* set);

/**
 * The anchor ns set, stores all NSs for a zone
 */
struct anchor_ns_set
{
    char* zone;
    struct map nss;
};

struct anchor_ns_set* anchor_ns_set_create();
struct anchor_ns_set* anchor_ns_set_from_rep(const char* zone, const struct reply_info *rep);
int anchor_ns_set_free(struct anchor_ns_set *set);
struct anchor_ns* anchor_ns_set_get(const struct anchor_ns_set* set, const char* name);
struct anchor_ns* anchor_ns_set_add(const struct anchor_ns_set* set, struct anchor_ns* ns);
int anchor_ns_set_equal(const struct anchor_ns_set *parent, const struct anchor_ns_set *child);

struct anchor_ns
{
    char* name;
    struct map ips;
};

struct anchor_ns *anchor_ns_create(const char *name);

// LOGGING FUNCTIONS
void anchor_ns_set_log(const struct anchor_ns_set *cache);
void anchor_ns_log(const struct anchor_ns *ns);

// HELPER FUNCTIONS
/**
 * Converts a domain to a fully qualified domain name
 * User should make sure there is enough space in the domain
 * @param domain the domain to convert
 * @return void
 */
void to_fqdn(char *domain);
int in_anchor_zones_list(const char *zonefile, const char *zone);
#endif // SERVICES_CACHE_ANCHOR_NS_H