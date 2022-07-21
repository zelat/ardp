//
// Created by Administrator on 2022/7/20.
//

#include <cstdint>
#include "apis.h"
#include "dpi_module.h"
#include "base/rcu_map.h"
#include "base/debug.h"
#include "dpi_session.h"
#include "dpi_debug.h"


// return true if packet is ingress to "lo" i/f
static bool proxymesh_packet_direction(io_ctx_t *ctx, dpi_packet_t *p) {
    io_app_t *app = NULL;
    if (p->eth_type == ETH_P_IP) {//ipv4

        struct iphdr *iph = (struct iphdr *) (p->pkt + p->l3);

        if (iph->saddr == iph->daddr) {
            app = dpi_ep_app_map_lookup(p->ep, p->dport, p->ip_proto);
            if (app != NULL) return false;
            app = dpi_ep_app_map_lookup(p->ep, p->sport, p->ip_proto);
            if (app != NULL) return true;
            return p->dport > p->sport;
        } else if (iph->daddr == htonl(INADDR_LOOPBACK) || IS_IN_LOOPBACK(ntohl(iph->daddr))) {
            return true;
        }
    } else {//ipv6
        struct ip6_hdr *ip6h = (struct ip6_hdr *) (p->pkt + p->l3);
        if (memcmp((uint8_t *) (ip6h->ip6_src.s6_addr), (uint8_t *) (ip6h->ip6_dst.s6_addr), 16) == 0) {
            app = dpi_ep_app_map_lookup(p->ep, p->dport, p->ip_proto);
            if (app != NULL) return false;
            app = dpi_ep_app_map_lookup(p->ep, p->sport, p->ip_proto);
            if (app != NULL) return true;
            return p->dport > p->sport;
        } else if (memcmp((uint8_t *) (ip6h->ip6_dst.s6_addr), (uint8_t *) (in6addr_loopback.s6_addr),
                          sizeof(ip6h->ip6_dst.s6_addr)) == 0) {
            return true;
        }
    }
    return false;
}

bool cmp_mac_prefix(void *m1, const char *prefix) {
    if (!m1 || !prefix) return false;
    return *(uint32_t *) m1 == *(uint32_t *) prefix;
}

bool dpi_is_ip4_internal(uint32_t ip) {
    int i;
    if (unlikely(th_internal_subnet4 == NULL) || (th_internal_subnet4->count == 0)) {
        return true;
    }
    for (i = 0; i < th_internal_subnet4->count; i++) {
        /*
        DEBUG_LOG(DBG_SESSION, NULL,
                  "ip="DBG_IPV4_FORMAT" mask="DBG_IPV4_FORMAT"/"DBG_IPV4_FORMAT"\n",
                  DBG_IPV4_TUPLE(ip), DBG_IPV4_TUPLE(th_internal_subnet4->list[i].ip),
                  DBG_IPV4_TUPLE(th_internal_subnet4->list[i].mask));
        */
        if ((ip & th_internal_subnet4->list[i].mask) == th_internal_subnet4->list[i].ip) {
            //    DEBUG_LOG(DBG_SESSION, NULL, "internal\n");
            return true;
        }
    }
    printf("internal:false\n");
    return false;
}

//return value is only used by nfq, 0 means accept, 1 drop
int dpi_recv_packet(io_ctx_t *ctx, uint8_t *ptr, int len) {
    int action, c;
    bool tap = false, inspect = true, isproxymesh = false;
    bool nfq = ctx->nfq;

    th_snap.tick = ctx->tick;

    memset(&th_packet, 0, offsetof(dpi_packet_t, EOZ));

    for (c = 0; c < DPI_SIG_CONTEXT_TYPE_MAX; c++) {
        th_packet.dlp_area[c].dlp_ptr = NULL;
        th_packet.dlp_area[c].dlp_len = 0;
        th_packet.dlp_area[c].dlp_start = 0;
        th_packet.dlp_area[c].dlp_end = 0;
        th_packet.dlp_area[c].dlp_offset = 0;
        th_packet.dlp_area[c].dlp_flags = 0;
    }
    th_packet.decoded_pkt.len = 0;

    th_packet.pkt = ptr;
    th_packet.cap_len = len;
    th_packet.l2 = 0;

    rcu_read_lock();

    th_internal_subnet4 = g_internal_subnet4;
    th_policy_addr = g_policy_addr;
    th_specialip_subnet4 = g_specialip_subnet4;
    th_xff_enabled = g_xff_enabled;

    if (likely(th_packet.cap_len >= sizeof(struct ethhdr))) {
        struct ethhdr *eth = (struct ethhdr *) (th_packet.pkt + th_packet.l2);
        io_mac_t *mac = NULL;

        // Lookup workloads
        if (!ctx->tc) {
            // NON-TC mode just fwd the mcast/bcast mac packet
            if (is_mac_m_b_cast(eth->h_dest)) {
                rcu_read_unlock();
                if (!tap && nfq) {
                    //bypass nfq in case of multicast or broadcast
                    return 0;
                }
                g_io_callback->send_packet(ctx, ptr, len);
                return 0;
            }

            if (mac_cmp(eth->h_source, ctx->ep_mac.ether_addr_octet)) {
                mac = (io_mac_t *) rcu_map_lookup(&g_ep_map, &eth->h_source);
            } else if (mac_cmp(eth->h_dest, ctx->ep_mac.ether_addr_octet)) {
                mac = (io_mac_t *) rcu_map_lookup(&g_ep_map, &eth->h_dest);
                th_packet.flags |= DPI_PKT_FLAG_INGRESS;
            }
        } else if (cmp_mac_prefix(eth->h_source, MAC_PREFIX)) {
            mac = (io_mac_t *) rcu_map_lookup(&g_ep_map, &eth->h_source);
        } else if (cmp_mac_prefix(eth->h_dest, MAC_PREFIX)) {
            mac = (io_mac_t *) rcu_map_lookup(&g_ep_map, &eth->h_dest);
            th_packet.flags |= DPI_PKT_FLAG_INGRESS;
        } else
            // For tapped port
            //check dst mac first because src mac may == dst mac for ingress
        if (mac_cmp(eth->h_dest, ctx->ep_mac.ether_addr_octet)) {
            mac = (io_mac_t *) rcu_map_lookup(&g_ep_map, &eth->h_dest);
            th_packet.flags |= DPI_PKT_FLAG_INGRESS;
        } else if (mac_cmp(eth->h_source, ctx->ep_mac.ether_addr_octet)) {
            mac = (io_mac_t *) rcu_map_lookup(&g_ep_map, &eth->h_source);
        } else if (cmp_mac_prefix(ctx->ep_mac.ether_addr_octet, PROXYMESH_MAC_PREFIX)) {
            /*
             * proxymesh injects its proxy service as a sidecar into POD,
             * ingress/egress traffic will be redirected to proxy, "lo"
             * interface is monitored to inspect traffic from and to proxy.
             */
            mac = (io_mac_t *) rcu_map_lookup(&g_ep_map, &ctx->ep_mac.ether_addr_octet);
            isproxymesh = true;
            if (th_session4_proxymesh_map.map == NULL) {
                dpi_session_proxymesh_init();
            }
        }
        if (likely(mac != NULL)) {
            tap = mac->ep->tap;

            th_packet.ctx = ctx;
            th_packet.ep = mac->ep;
            th_packet.ep_mac = mac->ep->mac->mac.ether_addr_octet;
            th_packet.ep_stats = &mac->ep->stats;
            th_packet.stats = &th_stats;

            IF_DEBUG_LOG(DBG_PACKET, &th_packet) {
                if (FLAGS_TEST(th_packet.flags, DPI_PKT_FLAG_INGRESS)) {
                    printf("pkt_mac=" DBG_MAC_FORMAT" ep_mac=" DBG_MAC_FORMAT"\n",
                           DBG_MAC_TUPLE(eth->h_dest), DBG_MAC_TUPLE(*th_packet.ep_mac));
                } else {
                    printf("pkt_mac=" DBG_MAC_FORMAT" ep_mac=" DBG_MAC_FORMAT"\n",
                           DBG_MAC_TUPLE(eth->h_source), DBG_MAC_TUPLE(*th_packet.ep_mac));
                }
            }

            if (!isproxymesh) {
                if (th_packet.flags & DPI_PKT_FLAG_INGRESS) {
                    th_packet.ep_all_metry = &th_packet.ep_stats->in;
                    th_packet.all_metry = &th_packet.stats->in;
                } else {
                    th_packet.ep_all_metry = &th_packet.ep_stats->out;
                    th_packet.all_metry = &th_packet.stats->out;
                }

                if (th_packet.ep_stats->cur_slot != ctx->stats_slot) {
                    dpi_catch_stats_slot(th_packet.ep_stats, ctx->stats_slot);
                }
                if (th_packet.stats->cur_slot != ctx->stats_slot) {
                    dpi_catch_stats_slot(th_packet.stats, ctx->stats_slot);
                }

                dpi_inc_stats_packet(&th_packet);
            }
        } else if (g_io_config->promisc) {
            th_packet.ctx = ctx;
            th_packet.flags |= (DPI_PKT_FLAG_INGRESS | DPI_PKT_FLAG_FAKE_EP);
            th_packet.ep = g_io_config->dummy_mac.ep;
            th_packet.ep_mac = g_io_config->dummy_mac.mac.ether_addr_octet;
            th_packet.ep_stats = &g_io_config->dummy_mac.ep->stats;
            th_packet.stats = &th_stats;
            th_packet.ep_all_metry = &th_packet.ep_stats->in;
            th_packet.all_metry = &th_packet.stats->in;
            tap = ctx->tap;
        } else {
            rcu_read_unlock();
            // If not in promisc mode, ignore flooded mac-mismatched pkts
            //bypass nfq
            return 0;

        }
    }

    // Parse after figuring out direction so that if there is any threat in the packet
    // it can be logged correctly
    action = dpi_parse_ethernet(&th_packet);
    if (unlikely(action == DPI_ACTION_DROP || action == DPI_ACTION_RESET)) {
        rcu_read_unlock();
        if (th_packet.frag_trac != NULL) {
            dpi_frag_discard(th_packet.frag_trac);
        }
        //no drop based on l2 decision because
        //nfq packet's l2 header is fake
        return 0;
    }

    if (isproxymesh) {
        //direction WRT "lo" i/f is opsite WRT to WL ep
        if (!proxymesh_packet_direction(ctx, &th_packet)) {
            th_packet.flags |= DPI_PKT_FLAG_INGRESS;
        }
        if (th_packet.flags & DPI_PKT_FLAG_INGRESS) {
            th_packet.ep_all_metry = &th_packet.ep_stats->in;
            th_packet.all_metry = &th_packet.stats->in;
        } else {
            th_packet.ep_all_metry = &th_packet.ep_stats->out;
            th_packet.all_metry = &th_packet.stats->out;
        }

        if (th_packet.ep_stats->cur_slot != ctx->stats_slot) {
            dpi_catch_stats_slot(th_packet.ep_stats, ctx->stats_slot);
        }
        if (th_packet.stats->cur_slot != ctx->stats_slot) {
            dpi_catch_stats_slot(th_packet.stats, ctx->stats_slot);
        }

        dpi_inc_stats_packet(&th_packet);
    }

    // Bypass broadcast, multicast and non-ip packet
    struct iphdr *iph;
    struct ip6_hdr *ip6h;
    switch (th_packet.eth_type) {
        case ETH_P_IP:
            iph = (struct iphdr *) (th_packet.pkt + th_packet.l3);
            if (INADDR_BROADCAST == ntohl(iph->daddr) || IN_MULTICAST(ntohl(iph->daddr))) {
                inspect = false;
            }
            break;
        case ETH_P_IPV6:
            ip6h = (struct ip6_hdr *) (th_packet.pkt + th_packet.l3);
            if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
                inspect = false;
            }
            break;
        default:
            inspect = false;
            break;
    }

    if (action == DPI_ACTION_NONE && inspect) {
        IF_DEBUG_LOG(DBG_PACKET, &th_packet) {
            debug_dump_packet(&th_packet);
        }
        action = dpi_inspect_ethernet(&th_packet);
        DEBUG_LOG(DBG_PACKET, NULL, "action=%d tap=%d inspect=%d\n",
                  action, tap, inspect);
    }

    rcu_read_unlock();

    if (likely(!tap && action != DPI_ACTION_DROP && action != DPI_ACTION_RESET &&
               action != DPI_ACTION_BLOCK)) {
        if (!tap && nfq) {
            //nfq accept after inspect l4/7
            return 0;
        }
        if (th_packet.frag_trac != NULL) {
            dpi_frag_send(th_packet.frag_trac, ctx);
        } else {
            g_io_callback->send_packet(ctx, ptr, len);
        }
    } else {
        if (th_packet.frag_trac != NULL) {
            dpi_frag_discard(th_packet.frag_trac);
        }
        if (!tap && nfq) {
            //nfq drop after inspect l4/7
            return 1;
        }
    }
    return 0;
}