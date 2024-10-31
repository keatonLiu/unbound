#include "services/cache/anchor_ns.h"
#include "anchor_ns.h"
#include "iterator/iter_delegpt.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>

struct anchor_ns_cache *anchor_ns_cache_create()
{
    struct anchor_ns_cache *cache = (struct anchor_ns_cache *)calloc(1, sizeof(struct anchor_ns_cache));
    if (!cache) {
        log_warn("anchor_ns_cache: memory allocation failed");
        return NULL;
    }
    cache->nss = (SimpleSet *)calloc(1, sizeof(SimpleSet));
    if (!cache->nss) {
        log_warn("anchor_ns_cache->nss: memory allocation failed");
        free(cache);
        return NULL;
    }
    set_init_alt(cache->nss, 1024, &anchor_ns_hash);
    return cache;
}

struct anchor_ns *anchor_ns_create(const char *name, const char *ip)
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
    a->ip = (const char *)calloc(strlen(ip) + 1, sizeof(char));
    if (!a->ip) {
        log_warn("anchor_ns->ip: memory allocation failed");
        free(a->name);
        free(a);
        return NULL;
    }
    strcpy(a->ip, ip);
}

static uint64_t anchor_ns_hash(const char *key)
{
    struct anchor_ns *ns = (struct anchor_ns *)key;
    size_t len = strlen(ns->name) + strlen(ns->ip) + 1;
    char buf[len + 1];
    snprintf(buf, sizeof(buf), "%s-%s", ns->name, ns->ip);

    size_t i;
    uint64_t h = 14695981039346656037ULL; // FNV_OFFSET 64 bit
    for (i = 0; i < len; ++i) {
        h = h ^ (unsigned char)buf[i];
        h = h * 1099511628211ULL; // FNV_PRIME 64 bit
    }
    return h;
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

int compare_anchor_ns_cache(struct anchor_ns_cache *parent, struct anchor_ns_cache *child)
{
    if (parent == NULL) {
        log_warn("parent anchor_ns_cache is NULL");
        return 1;
    }

    if (child == NULL) {
        log_warn("child anchor_ns_cache is NULL");
        return 1;
    }

    if (parent->nss == NULL || child->nss == NULL) {
        log_warn("parent or child anchor_ns_cache->nss is NULL");
        return 1;
    }

    int cmp = set_cmp(parent->nss, child->nss);
    if (cmp == SET_EQUAL) {
        log_info("anchor_ns_cache: parent and child NSs are equal");
        log_anchor_ns_set(parent->nss);
        return 0;
    }

    log_warn("anchor_ns_cache: parent and child NSs are not equal");
    log_warn("Old NSs:");
    uint64_t i;
    log_anchor_ns_set(parent->nss);

    log_warn("New NSs:");
    log_anchor_ns_set(child->nss);

    return 1;
}

void log_anchor_ns_set(const SimpleSet *set)
{
    uint64_t i;
    for (i = 0; i < set->number_nodes; ++i) {
        if (set->nodes[i] != NULL) {
            const struct anchor_ns *ns = (const struct anchor_ns *)set->nodes[i]->_key;
            log_warn("NS: %s, IP: %s", ns->name, ns->ip);
        }
    }
}