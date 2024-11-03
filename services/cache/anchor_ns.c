#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "services/cache/anchor_ns.h"
#include "iterator/iter_delegpt.h"
#include "util/log.h"
#include "util/net_help.h"

struct anchor_ns_cache *anchor_ns_cache_create() {
    struct anchor_ns_cache *cache = (struct anchor_ns_cache *)calloc(1, sizeof(struct anchor_ns_cache));
    if (!cache) {
        log_warn("anchor_ns_cache: memory allocation failed");
        return NULL;
    }
    cache->zones = (SimpleSet *)calloc(1, sizeof(SimpleSet));
    if (!cache->zones) {
        log_warn("anchor_ns_cache->zones: memory allocation failed");
        free(cache);
        return NULL;
    }
    set_init_alt(cache->zones, 1024, anchor_ns_set_hash);
    return cache;
}

struct anchor_ns_set* anchor_ns_cache_get(struct anchor_ns_cache* cache, const char *zone) {
    struct anchor_ns_set set;
    set.zone = (char*)zone;
    uint64_t index;
    if (set_get(cache->zones, (const char *)&set, &index) == SET_TRUE) {
        return (struct anchor_ns_set *)cache->zones->nodes[index]->_key;
    }
    return NULL;
}

int anchor_ns_cache_set(const struct anchor_ns_cache *cache, const struct anchor_ns_set *set) {
    return set_add(cache->zones, (const char *)set);
}

struct anchor_ns_set *anchor_ns_set_create() {
    struct anchor_ns_set *cache = (struct anchor_ns_set *)calloc(1, sizeof(struct anchor_ns_set));
    if (!cache) {
        log_warn("anchor_ns_set: memory allocation failed");
        return NULL;
    }
    cache->nss = (SimpleSet *)calloc(1, sizeof(SimpleSet));
    if (!cache->nss) {
        log_warn("anchor_ns_set->nss: memory allocation failed");
        free(cache);
        return NULL;
    }
    cache->zone = NULL;
    set_init_alt(cache->nss, 1024, anchor_ns_hash);
    return cache;
}

struct anchor_ns *anchor_ns_create(const char *name) {
    struct anchor_ns *a = (struct anchor_ns *)malloc(sizeof(struct anchor_ns));
    if (!a) {
        log_warn("anchor_ns: memory allocation failed");
    }
    a->name = (char *)calloc(strlen(name) + 1, sizeof(char));
    if (!a->name) {
        log_warn("anchor_ns->name: memory allocation failed");
        free(a);
        return NULL;
    }
    strcpy(a->name, name);
    a->ips = (SimpleSet *)calloc(1, sizeof(SimpleSet));
    if (!a->ips) {
        log_warn("anchor_ns->ips: memory allocation failed");
        free((void *)a->name);
        free(a);
        return NULL;
    }
    set_init(a->ips); // string comparison
    return a;
}

uint64_t anchor_ns_hash(const char *key) {
    struct anchor_ns *ns = (struct anchor_ns *)key;
    return default_hash(ns->name);
}

uint64_t anchor_ns_set_hash(const char* key) {
    struct anchor_ns_set *ns = (struct anchor_ns_set *)key;
    return default_hash(ns->zone);
}

void to_fqdn(char *domain) {
    size_t len = strlen(domain);

    // Check if domain already has a '.' at the end
    if (len > 0 && domain[len - 1] != '.') {
        // Add a '.' at the end
        if (len < 255) { 
            domain[len] = '.';
            domain[len + 1] = '\0';
        }
    }
}

int in_anchor_zones_list(const char *zonefile, const char *zone) {
    FILE *file = fopen(zonefile, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return -1;
    }
    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        to_fqdn(line);
        if (strcmp(line, zone) == 0) {
            fclose(file);
            return 1; 
        }
    }

    fclose(file);
    return 0;
}

int anchor_ns_set_compare(const struct anchor_ns_set *parent, const struct anchor_ns_set *child) {
    if (parent == NULL) {
        log_warn("parent anchor_ns_set is NULL");
        return 0;
    }

    if (child == NULL) {
        log_warn("child anchor_ns_set is NULL");
        return 0;
    }

    if (parent->nss == NULL || child->nss == NULL) {
        log_warn("parent or child anchor_ns_set->nss is NULL");
        return 0;
    }

    int cmp = set_cmp(parent->nss, child->nss);
    if (cmp == SET_EQUAL) {
        log_info("anchor_ns_set: parent and child NSs are equal");
        anchor_ns_set_log(parent);
        return 0;
    }

    log_warn("anchor_ns_set: parent and child NSs are not equal");
    log_warn("Old NSs:");
    uint64_t i;
    anchor_ns_set_log(parent);

    log_warn("New NSs:");
    anchor_ns_set_log(child);

    return 1;
}

void anchor_ns_set_log(const struct anchor_ns_set *cache) {
    uint64_t i;
    log_info("NSs for zone: %s", cache->zone);
    for (i = 0; i < cache->nss->number_nodes; ++i) {
        if (cache->nss->nodes[i] != NULL) {
            anchor_ns_log((const struct anchor_ns*)cache->nss->nodes[i]);
        }
    }
}

void anchor_ns_log(const struct anchor_ns *ns) {
    uint64_t i;
    log_info("NS: %s", ns->name);
    for (i = 0; i < ns->ips->number_nodes; ++i) {
        if (ns->ips->nodes[i] != NULL) {
            log_info(" - IP: %s", (const char *)ns->ips->nodes[i]);
        }
    }
}

struct anchor_ns_set *anchor_ns_set_from_rep(const char* zone, const struct reply_info *rep) {
    struct anchor_ns_set *set = anchor_ns_set_create();
    if (set == NULL) {
        return NULL;
    }
    set->zone = (char *)calloc(strlen(zone) + 1, sizeof(char));
    if (set->zone == NULL) {
        log_warn("Failed to allocate memory for zone");
        return NULL;
    }
    strcpy((char *)set->zone, zone);
    size_t i;
    for (i= rep->an_numrrsets; i<rep->an_numrrsets+rep->ns_numrrsets; i++) {
        struct ub_packed_rrset_key *rrset = rep->rrsets[i];
        struct packed_rrset_data *data = (struct packed_rrset_data *)rrset->entry.data;
        size_t j;
        uint16_t type = ntohs(rrset->rk.type);
        if (type == LDNS_RR_TYPE_NS) {
            for (j = 0; j < data->count; j++) {
                char *name = (char *)data->rr_data[j];
                struct anchor_ns *ns = anchor_ns_create(name);
                if (ns == NULL) {
                    log_warn("Failed to create anchor_ns");
                    return NULL;
                }
                set_add(set->nss, (const char*)ns);
            }
        }
    }

    // add ips to anchor_ns from parent side glue
    for (i = 0; i < rep->rrset_count; i++) {
        /* skip auth section. FIXME really needed?*/
        if(rep->an_numrrsets <= i && 
			i < (rep->an_numrrsets+rep->ns_numrrsets))
			continue;
        struct ub_packed_rrset_key *rrset = rep->rrsets[i];
        struct packed_rrset_data *data = (struct packed_rrset_data *)rrset->entry.data;
        size_t j;
        uint16_t type = ntohs(rrset->rk.type);
        if (type == LDNS_RR_TYPE_A) {
            for (j = 0; j < data->count; j++) {
                if(data->rr_len[i] != 2 + INET_SIZE)
                    continue;
                struct sockaddr_in sa;
                memmove(&sa.sin_addr, data->rr_data[i]+2, INET_SIZE);
                char dest[100];
                inet_ntop(AF_INET, &sa.sin_addr, dest, (socklen_t)sizeof(dest));
                char *ip = calloc(strlen(dest) + 1, sizeof(char));
                if (ip == NULL) {
                    log_warn("Failed to allocate memory for ip");
                    return NULL;
                }
                strcpy(ip, dest);
                struct anchor_ns *ns = anchor_ns_create((const char *)rrset->rk.dname);
                if (ns == NULL) {
                    log_warn("Failed to create anchor_ns");
                    return NULL;
                }
                set_add(ns->ips, ip);
            }
        }
    }

    return set;
}