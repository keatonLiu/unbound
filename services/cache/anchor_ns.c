#include "services/cache/anchor_ns.h"
#include "anchor_ns.h"
#include "iterator/iter_delegpt.h"
#include "util/log.h"
#include "util/data/msgreply.h"
#include <stdio.h>
#include <stdlib.h>
#include "util/net_help.h"
#include <netinet/in.h>

struct anchor_ns_cache *anchor_ns_cache_create()
{
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
    set_init(cache->zones); // string comparison
    return cache;
}

struct anchor_ns_set *anchor_ns_set_create()
{
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
    set_init_alt(cache->nss, 1024, &anchor_ns_hash);
    return cache;
}

struct anchor_ns *anchor_ns_create(const char *name)
{
    struct anchor_ns *a = (struct anchor_ns *)malloc(sizeof(struct anchor_ns));
    if (!a) {
        log_warn("anchor_ns: memory allocation failed");
    }
    a->name = (const char *)calloc(strlen(name) + 1, sizeof(char));
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

static uint64_t anchor_ns_hash(const char *key)
{
    struct anchor_ns *ns = (struct anchor_ns *)key;
    return default_hash(ns->name);
}

static uint64_t anchor_ns_set_hash(const char* key) {
    struct anchor_ns_set *ns = (struct anchor_ns_set *)key;
    return default_hash(ns->zone);
}

void to_fqdn(char *domain)
{
    size_t len = strlen(domain);

    // 检查域名末尾是否已经有 '.'
    if (len > 0 && domain[len - 1] != '.') {
        // 在末尾添加 '.' 转为 FQDN
        if (len < 255) { // 防止越界，符合 DNS 最大长度
            domain[len] = '.';
            domain[len + 1] = '\0';
        }
    }
}

int in_anchor_zones_list(const char *zonefile, const char *zone)
{
    FILE *file = fopen(zonefile, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return -1; // 打开文件失败
    }
    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        // 移除读取行末尾的换行符
        line[strcspn(line, "\n")] = '\0';
        to_fqdn(line);
        // 比较读取的行和传入的 zone
        if (strcmp(line, zone) == 0) {
            fclose(file);
            return 1; // 找到匹配行
        }
    }

    fclose(file);
    return 0; // 没有找到匹配行
}

int compare_anchor_ns_set(struct anchor_ns_set *parent, struct anchor_ns_set *child)
{
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
        log_anchor_ns_set(parent->nss);
        return 0;
    }

    log_warn("anchor_ns_set: parent and child NSs are not equal");
    log_warn("Old NSs:");
    uint64_t i;
    log_anchor_ns_set(parent->nss);

    log_warn("New NSs:");
    log_anchor_ns_set(child->nss);

    return 1;
}

void log_anchor_ns_set(const struct anchor_ns_set *cache)
{
    uint64_t i;
    log_info("NSs for zone: %s", cache->zone);
    for (i = 0; i < cache->nss->number_nodes; ++i) {
        if (cache->nss->nodes[i] != NULL) {
            log_anchor_ns((const struct anchor_ns*)cache->nss->nodes[i]);
        }
    }
}

void log_anchor_ns(const struct anchor_ns *ns) {
    uint64_t i;
    log_info("NS: %s", ns->name);
    for (i = 0; i < ns->ips->number_nodes; ++i) {
        if (ns->ips->nodes[i] != NULL) {
            log_info(" - IP: %s", (const char *)ns->ips->nodes[i]);
        }
    }
}

struct anchor_ns_set *anchor_ns_set_from_rep(struct reply_info *rep)
{
    struct anchor_ns_set *set = anchor_ns_set_create();
    if (set == NULL) {
        return NULL;
    }

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
                set_insert(set->nss, ns);
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
                set_insert(ns->ips, ip);
            }
        }
    }

    return set;
}