//
// Created by tanchao on 2022/7/20.
//

#include "dpi_session.h"
#include "base/debug.h"
#include "dpi_module.h"
#include "dpi_policy.h"

namespace dpi {
    static int session4_proxymesh_match(struct cds_lfht_node *ht_node, const void *key) {
        dpi_session_t *s = STRUCT_OF(ht_node, dpi_session_t, node);
        const dpi_session_t *k = (dpi_session_t *) key;
        int matched = 0;

        if (s->client.ip.ip4 == k->client.ip.ip4 &&
            s->client.port == k->client.port &&
            s->ip_proto == k->ip_proto) {
            matched = 1;
            if (s->server.ip.ip4 == htonl(INADDR_LOOPBACK) &&
                s->client.ip.ip4 != htonl(INADDR_LOOPBACK)) {
                s->server.ip.ip4 = k->server.ip.ip4;
                s->server.port = k->server.port;

                s->policy_desc.flags &= ~(POLICY_DESC_INTERNAL | POLICY_DESC_EXTERNAL);
                if (FLAGS_TEST(s->flags, DPI_SESS_FLAG_INGRESS)) {
                    s->policy_desc.flags |= dpi_is_ip4_internal(s->client.ip.ip4) ?
                                            POLICY_DESC_INTERNAL : POLICY_DESC_EXTERNAL;
                } else {
                    s->policy_desc.flags |= dpi_is_ip4_internal(s->server.ip.ip4) ?
                                            POLICY_DESC_INTERNAL : POLICY_DESC_EXTERNAL;
                }
            }
        }

        return matched;
    }

    static uint32_t session4_proxymesh_hash(const void *key) {
        const dpi_session_t *k = (dpi_session_t *) key;
        uint32_t port = k->client.port;

        return sdbm_hash((uint8_t *) &k->client.ip, 4) +
               sdbm_hash((uint8_t *) &port, sizeof(port));
    }

    static int session6_proxymesh_match(struct cds_lfht_node *ht_node, const void *key) {
        dpi_session_t *s = STRUCT_OF(ht_node, dpi_session_t, node);
        const dpi_session_t *k = (dpi_session_t *) key;
        int matched = 0;

        if (memcmp(&s->client.ip, &k->client.ip, sizeof(k->client.ip)) == 0 &&
            s->client.port == k->client.port && s->ip_proto == k->ip_proto) {
            matched = 1;
            if (memcmp((uint8_t *) &s->server.ip, (uint8_t *) (in6addr_loopback.s6_addr), sizeof(s->server.ip)) == 0 &&
                memcmp((uint8_t *) &s->client.ip, (uint8_t *) (in6addr_loopback.s6_addr), sizeof(s->client.ip)) != 0) {
                memcpy(&s->server.ip, &k->server.ip, sizeof(s->server.ip));
                s->server.port = k->server.port;
            }
        }

        return matched;
    }

    static uint32_t session6_proxymesh_hash(const void *key) {
        const dpi_session_t *k = (dpi_session_t *) key;
        uint32_t port = k->client.port;

        return sdbm_hash((uint8_t *) &k->client.ip, sizeof(k->client.ip)) +
               sdbm_hash((uint8_t *) &port, sizeof(port));
    }

    void dpi_session_proxymesh_init(void) {
//        DEBUG_LOG_FUNC_ENTRY(DBG_INIT | DBG_SESSION, NULL);

        rcu_map_init(&th_session4_proxymesh_map, 64, offsetof(dpi_session_t, node),
                     session4_proxymesh_match, session4_proxymesh_hash);
        rcu_map_init(&th_session6_proxymesh_map, 32, offsetof(dpi_session_t, node),
                     session6_proxymesh_match, session6_proxymesh_hash);
    }
}