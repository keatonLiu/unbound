#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "services/cache/anchor_ns.h"
#include "iterator/iter_delegpt.h"
#include "util/log.h"
#include "util/net_help.h"
#include "util/data/dname.h"
#include "util/regional.h"
#include "sldns/sbuffer.h"

struct anchor_ns_cache *anchor_ns_cache_create(const char* db_path) {
    struct anchor_ns_cache *cache = (struct anchor_ns_cache *)calloc(1, sizeof(struct anchor_ns_cache));
    if (!cache) {
        log_warn("anchor_ns_cache: memory allocation failed");
        return NULL;
    }
    map_init(&cache->zones, default_cmp_func_str); // key = zone
    cache->db_path = db_path;
    log_info("Opening database: %s", db_path);
    if (sqlite3_open(db_path, &cache->db) != SQLITE_OK) {
        log_warn("Failed to open database: %s", sqlite3_errmsg(cache->db));
        return NULL;
    }

    const char *sql = 
        "CREATE TABLE IF NOT EXISTS zone ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    name TEXT NOT NULL"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_name ON zone(name);";
    char *err_msg = NULL;
    int rc = sqlite3_exec(cache->db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        log_err("Failed to create table: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(cache->db);
        return NULL;
    }
    return cache;
}

struct anchor_ns_set* anchor_ns_cache_get(const struct anchor_ns_cache* cache, const char *zone) {
    return (struct anchor_ns_set *)map_get(cache->zones, zone);
}

struct anchor_ns_set* anchor_ns_cache_set(const struct anchor_ns_cache *cache, struct anchor_ns_set *set) {
    return (struct anchor_ns_set*)map_insert(cache->zones, set->zone, set);
}

int anchor_ns_cache_free(struct anchor_ns_cache *cache) {
    sqlite3_close(cache->db);
    map_node_type *node;
    RBTREE_FOR(node, map_node_type *, cache->zones.tree) {
        struct anchor_ns_set *set = (struct anchor_ns_set *)node->data;
        anchor_ns_set_free(set);
    }
    map_delete(cache->zones);
    free(cache);
    return 1;
}

struct anchor_ns_set *anchor_ns_set_create() {
    struct anchor_ns_set *cache = (struct anchor_ns_set *)calloc(1, sizeof(struct anchor_ns_set));
    if (!cache) {
        log_warn("anchor_ns_set: memory allocation failed");
        return NULL;
    }
    map_init(&cache->nss, default_cmp_func_str); // key = name
    cache->zone = NULL;
    return cache;
}

struct anchor_ns* anchor_ns_set_get(const struct anchor_ns_set* set, const char* name) {
    return (struct anchor_ns *)map_get(set->nss, name);
}


int anchor_ns_set_equal(const struct anchor_ns_set *parent, const struct anchor_ns_set *child) {
    if (parent == NULL) {
        log_warn("parent anchor_ns_set is NULL");
        return 0;
    }

    if (child == NULL) {
        log_warn("child anchor_ns_set is NULL");
        return 0;
    }

    int equal = 1;
    if (parent->nss.tree->count == child->nss.tree->count) {
        map_node_type *node;
        RBTREE_FOR(node, map_node_type *, parent->nss.tree) {
            struct anchor_ns *ns = (struct anchor_ns *)node->data;
            struct anchor_ns *child_ns = anchor_ns_set_get(child, ns->name);
            if (child_ns == NULL) {
                equal = 0;
                break;
            }
        }
    } else {
        equal = 0;
    }
    return equal;
}

struct anchor_ns* anchor_ns_set_add(const struct anchor_ns_set* set, struct anchor_ns* ns){
    return (struct anchor_ns*)map_insert(set->nss, ns->name, ns);
}

struct anchor_ns_set *anchor_ns_set_from_rep(const char* zone, const struct reply_info *rep, struct regional* region) {
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
    for (i= 0; i<rep->an_numrrsets+rep->ns_numrrsets; i++) {
        struct ub_packed_rrset_key *rrset = rep->rrsets[i];
        struct packed_rrset_data *data = (struct packed_rrset_data *)rrset->entry.data;
        size_t j;
        uint16_t type = ntohs(rrset->rk.type);
        if (type == LDNS_RR_TYPE_NS) {
            for (j = 0; j < data->count; j++) {
                if(data->rr_len[j] < 2+1) continue; /* len + root label */
                size_t len = dname_valid(data->rr_data[j]+2, data->rr_len[j]-2);
                if(len != (size_t)sldns_read_uint16(data->rr_data[j]))
                    continue; /* bad format */
                char name[len+1];
                dname_str(data->rr_data[j]+2, name);
                struct anchor_ns *ns = anchor_ns_create(name);
                if (ns == NULL) {
                    log_warn("Failed to create anchor_ns");
                    return NULL;
                }
                anchor_ns_set_add(set, ns);
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
                if(data->rr_len[j] != 2 + INET_SIZE)
                    continue;
                struct sockaddr_in sa;
                memmove(&sa.sin_addr, data->rr_data[j]+2, INET_SIZE);
                char dest[100];
                inet_ntop(AF_INET, &sa.sin_addr, dest, (socklen_t)sizeof(dest));
                /* allocated ips at region, so we don't need to free them */
                char *ip = regional_alloc(region, strlen(dest) + 1);
                if (ip == NULL) {
                    log_warn("Failed to allocate memory for ip");
                    return NULL;
                }
                strcpy(ip, dest);

                char name[rrset->rk.dname_len + 1];
                dname_str(rrset->rk.dname, name);
                struct anchor_ns *ns = anchor_ns_set_get(set, name);
                if (ns == NULL) {
                    log_warn("Failed to create anchor_ns");
                    return NULL;
                }
                map_insert(ns->ips, ip, ip);
            }
        }
    }
    return set;
}

int anchor_ns_set_free(struct anchor_ns_set *set) {
    if (set == NULL) {
        return 0;
    }
    map_node_type *node;
    RBTREE_FOR(node, map_node_type *, set->nss.tree) {
        struct anchor_ns *ns = (struct anchor_ns *)node->data;
        map_delete(ns->ips);
        /* no need to free each ip string, cause they were allocated at qstate region */
        free(ns->name);
        free(ns);
    }
    free(set->zone);
    map_delete(set->nss);
    free(set);
    return 1;
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
    map_init(&a->ips, default_cmp_func_str);
    return a;
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

int in_anchor_zones_list(sqlite3 *db, const char *zone) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT 1 FROM zone WHERE name = ? LIMIT 1";

    // 准备 SQL 查询
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return false;
    }

    // 绑定参数
    if (sqlite3_bind_text(stmt, 1, zone, -1, SQLITE_STATIC) != SQLITE_OK) {
        fprintf(stderr, "Failed to bind parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return false;
    }

    // 执行查询并检查结果
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    
    // 清理
    sqlite3_finalize(stmt);
    return exists;
}


void anchor_ns_set_log(const struct anchor_ns_set *cache) {
    uint64_t i;
    log_info("NSs for zone: %s", cache->zone);
    map_node_type *node;
    RBTREE_FOR(node, map_node_type *, cache->nss.tree) {
        anchor_ns_log((const struct anchor_ns*)node->data);
    }
}

void anchor_ns_log(const struct anchor_ns *ns) {
    uint64_t i;
    log_info("NS: %s", ns->name);
    map_node_type *node;
    RBTREE_FOR(node, map_node_type *, ns->ips.tree) {
        log_info(" -IP: %s", (const char*)node->data);
    }
}

int anchor_ns_free(struct anchor_ns *ns) {
    if (ns == NULL) {
        return 0;
    }
    map_node_type *node;
    /* no need to free each ip string, cause they were allocated at qstate region */
    // RBTREE_FOR(node, map_node_type *, ns->ips.tree) {
        // free((char *)node->data);
    // }
    map_delete(ns->ips);
    free(ns->name);
    free(ns);
    return 1;
}
