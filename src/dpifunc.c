#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_log.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_hash.h>

#include <pcap.h>

#include "dpdkframework.h"
#include "xfdpi.h"

static struct ndpi_detection_module_struct *g_ndpi_module = NULL;

#define ETH_HDR_LEN 14
#define TICK_RESOLUTION          1000

int appflow_idle_timeout = 10;   // in sec

// static struct rte_mempool *g_appflow_pool[CORES_PER_TEST_MAX];

APPFLOW_T *g_appflows = NULL;
static struct rte_hash *appflows_ipv4_tcp_hash = NULL;

static int appflows_aging_add_ind = 0;
static int appflows_aging_remove_ind = 1;
static struct list_head g_appflows_aging[APPFLOWS_AGE_LIST_HASH_SIZE];

struct distributor_stat_t *gp_distributor_stat = NULL;

static int appflow_age_refresh(APPFLOW_T *flow)
{
    flow->appflow_age = appflow_idle_timeout;

    return 0;
}

static int destroy_one_appflow(APPFLOW_T *flow)
{
    int pos = APPFLOW_POS(flow);
    char *key;

    if(rte_hash_get_key_with_position(appflows_ipv4_tcp_hash, pos, (void **)&key) < 0){
        gp_distributor_stat->distributor_err.hash_invald++;
        return -1;
    }
    if(rte_hash_del_key(appflows_ipv4_tcp_hash, key) < 0){
        gp_distributor_stat->distributor_err.hash_invald++;
        return -1;
    }

    gp_distributor_stat->flow_hash_remove_cnt++;
    
    return 0;
}

static int appflow_upload_buffed_to_protocol_st(APPFLOW_T *flow)
{
    PROTOCOL_STATS_T *st = &gp_distributor_stat->protocol_stats[flow->detected_ndpi_protocol.app_protocol];

    st->detect_bytes += flow->buffed_bytes_cnt;
    st->detect_pkts += flow->buffed_pkts_cnt;

    return 0;
}

// call every ms
int appflow_aging_do(int nslots)
{
    struct list_head *p, *n;
    struct list_head *head;
    APPFLOW_T *flow;
        
    while(nslots){
        head = &g_appflows_aging[appflows_aging_remove_ind];
        list_for_each_safe(p, n, head){
            flow = list_entry(p, APPFLOW_T, appflow_aging_list);
            if(flow->appflow_age > 0){
                flow->appflow_age--;
            }else{
                list_del(&flow->appflow_aging_list);
                gp_distributor_stat->flow_timeout_cnt++;
                gp_distributor_stat->aging_list_remove_cnt++;
                if(flow->appflow_st == APPFLOWS_ST_DETECTING){
                    appflow_upload_buffed_to_protocol_st(flow);
                    gp_distributor_stat->flow_detect_fail_cnt++;
                }
                destroy_one_appflow(flow);
            }
        }
        nslots--;

        appflows_aging_remove_ind++;
        if(appflows_aging_remove_ind >= APPFLOWS_AGE_LIST_HASH_SIZE){
            appflows_aging_remove_ind = 0;
        }
    }

    return 0;
}

static int add_appflow_to_aging_list(APPFLOW_T *flow)
{
    list_add_tail(&flow->appflow_aging_list, &g_appflows_aging[appflows_aging_add_ind]);
    appflows_aging_add_ind++;
    if(appflows_aging_add_ind >= APPFLOWS_AGE_LIST_HASH_SIZE){
        appflows_aging_add_ind = 0;
    }
    gp_distributor_stat->aging_list_add_cnt++;
    
    return 0;
}

static int get_ipv4_tcp_info(const char *dpdkdat, int caplen, uint32_t *srcip, uint32_t *dstip, uint16_t *srcport, uint16_t *dstport)
{
    struct ether_hdr *ethhdr;
    struct ipv4_hdr *ipv4hdr;
    struct tcp_hdr *tcp_hdr;

    ethhdr = (struct ether_hdr *)dpdkdat;
    
    if(likely(ntohs(ethhdr->ether_type) == ETHER_TYPE_IPv4)){
        ipv4hdr = (struct ipv4_hdr *)(dpdkdat + ETHER_HDR_LEN);
        *srcip = htonl(ipv4hdr->src_addr);
        *dstip = htonl(ipv4hdr->dst_addr);
        if(likely(ipv4hdr->next_proto_id == IPPROTO_TCP)){
            tcp_hdr = (struct tcp_hdr *)((char *)ipv4hdr + (ipv4hdr->version_ihl & 0x0f) * 4);
            *srcport = ntohs(tcp_hdr->src_port);
            *dstport = ntohs(tcp_hdr->dst_port);
        }else{
            return -1;
        }
    }else{
        return -1;
    }

    return 0;
}

static int appflow_change_st(APPFLOW_T *flow, int newst)
{
    flow->appflow_st = newst;
    return 0;
}

static inline int init_one_appflow(APPFLOW_T *flow)
{
    memset(flow, 0, sizeof(APPFLOW_T));

    appflow_change_st(flow, APPFLOWS_ST_DETECTING);
    flow->detected_ndpi_protocol.app_protocol = NDPI_PROTOCOL_UNKNOWN;
    return 0;
}

static int get_hashbuff_from_ipv4_tcp(uint8_t *hashbuff, uint32_t srcip, uint32_t dstip, uint16_t srcport, uint16_t dstport)
{
    int swap = 0;

    if(srcport < dstport){
    }else if(srcport == dstport){
        if(srcip < dstip){
        }else if(srcip == dstip){
        }else{
            swap = 1;
        }
    }else{
        swap = 1;
    }

    if(swap){
        *(uint32_t *)hashbuff = dstip;
        *(uint16_t *)((char *)hashbuff + 4) = dstport;
        *(uint32_t *)((char *)hashbuff + 6) = srcip;
        *(uint16_t *)((char *)hashbuff + 10) = srcport;
    }else{
        *(uint32_t *)hashbuff = srcip;
        *(uint16_t *)((char *)hashbuff + 4) = srcport;
        *(uint32_t *)((char *)hashbuff + 6) = dstip;
        *(uint16_t *)((char *)hashbuff + 10) = dstport;
    }

    return 0;
}

static int appflow_upload_protocol_st(APPFLOW_T *flow, int pktlen)
{
    PROTOCOL_STATS_T *st = &gp_distributor_stat->protocol_stats[flow->detected_ndpi_protocol.app_protocol];

    st->detect_bytes += pktlen;
    st->detect_pkts++;

    return 0;
}

static inline int process_packet_real(APPFLOW_T *flow, const char *iphdr, int len, uint64_t ms)
{
    flow->detected_ndpi_protocol = ndpi_detection_process_packet(g_ndpi_module, &flow->ndpi_flow_sm, (const u_char *)iphdr, len, ms, &flow->ndpi_flow_sm_src, &flow->ndpi_flow_sm_dst);

    if(flow->detected_ndpi_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN){
        appflow_change_st(flow, APPFLOWS_ST_DETECTED);
        gp_distributor_stat->flow_detected_cnt++;
        appflow_upload_buffed_to_protocol_st(flow);
        return 0;
    }
    
    return -1;
}

static inline int process_one_appflow(APPFLOW_T *flow, const char *pkt, int pktlen, uint64_t ms)
{
    int ret;

    appflow_age_refresh(flow);

    switch(flow->appflow_st){
        case APPFLOWS_ST_DETECTING:
            flow->buffed_pkts_cnt++;
            flow->buffed_bytes_cnt += pktlen;
    
            flow->inspected_pkts_cnt++;
            ret = process_packet_real(flow, (const char *)&pkt[ETH_HDR_LEN], pktlen - ETH_HDR_LEN, ms);
            if(ret < 0){
                if(flow->inspected_pkts_cnt >= MAX_INSPECT_PKTS_CNT){
                    appflow_change_st(flow, APPFLOWS_ST_DETECT_FAIL);
                    gp_distributor_stat->flow_detect_fail_cnt++;
                    appflow_upload_buffed_to_protocol_st(flow);
                }
            }
            break;
        case APPFLOWS_ST_DETECTED:
            appflow_upload_protocol_st(flow, pktlen);
            break;
        case APPFLOWS_ST_DETECT_FAIL:
            appflow_upload_protocol_st(flow, pktlen);
            break;
        default:
            break;
    }

    return 0;
}

int dpdk_process_packet_one_real(struct rte_mbuf *m)
{
    char *packet;
    int packetlen;
    uint32_t srcip;
    uint32_t dstip;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t hashbuff[APPFLOWS_HASH_LEN];
    int pos;
    APPFLOW_T *appflow;
    
    packet = rte_pktmbuf_mtod(m, char *);
    packetlen = rte_pktmbuf_pkt_len(m);

    if(get_ipv4_tcp_info(packet, packetlen, &srcip, &dstip, &srcport, &dstport) < 0){
        gp_distributor_stat->ignored_pkt_cnt++;
        goto exit;
    }
    get_hashbuff_from_ipv4_tcp(hashbuff, srcip, dstip, srcport, dstport);

    pos = rte_hash_lookup(appflows_ipv4_tcp_hash, hashbuff);
    if(pos >= 0){
        appflow = &g_appflows[pos];
    }else{
        pos = rte_hash_add_key(appflows_ipv4_tcp_hash, &hashbuff);
        if(pos < 0){
            gp_distributor_stat->distributor_err.hash_full++;
            goto exit;
        }
        appflow = &g_appflows[pos];
        init_one_appflow(appflow);
        add_appflow_to_aging_list(appflow);
        gp_distributor_stat->flow_hash_add_cnt++;
    }

    process_one_appflow(appflow, packet, packetlen, dkfw_elapsed_ms);

exit:
    
    rte_pktmbuf_free(m);

    return 0;
}

static void *malloc_wrapper(size_t size) {
    return rte_malloc(NULL, size, 64);
}

static void free_wrapper(void *freeable) {
    rte_free(freeable);
}

int init_ndpi_base(void)
{
    int i;
    char buff[64];
    NDPI_PROTOCOL_BITMASK all;
    struct rte_hash_parameters params;
    int proc = dkfw_my_proc_ind();

    if(IS_DISPATCH_CORE){
        return 0;
    }
    
    g_ndpi_module = ndpi_init_detection_module();
    if(!g_ndpi_module){
        return -1;
    }

    set_ndpi_malloc(malloc_wrapper), set_ndpi_free(free_wrapper);

    for(i=0;i<APPFLOWS_AGE_LIST_HASH_SIZE;i++){
        INIT_LIST_HEAD(&g_appflows_aging[i]);
    }

    ndpi_set_detection_preferences(g_ndpi_module, ndpi_pref_http_dont_dissect_response, 0);
    ndpi_set_detection_preferences(g_ndpi_module, ndpi_pref_dns_dont_dissect_response, 0);
    ndpi_set_detection_preferences(g_ndpi_module, ndpi_pref_direction_detect_disable, 0);
    ndpi_set_detection_preferences(g_ndpi_module, ndpi_pref_disable_metadata_export, 0);

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(g_ndpi_module, &all);

    g_appflows = malloc(sizeof(APPFLOW_T) * APPFLOWS_MAX);
    if(!g_appflows){
        printf("create appflow fail.\n");
        return -1;
    }
    memset(g_appflows, 0, sizeof(APPFLOW_T) * APPFLOWS_MAX);

    snprintf(buff, sizeof(buff), "appflowH%d", proc);
    memset(&params, 0, sizeof(params));
    params.name = buff;
    params.entries = APPFLOWS_MAX;
    params.key_len = APPFLOWS_HASH_LEN;
    params.socket_id = SOCKET_ID_ANY;
    appflows_ipv4_tcp_hash = rte_hash_create(&params);
    if(!appflows_ipv4_tcp_hash){
        printf("create appflow hash error.\n");
        return -1;
    }

    gp_distributor_stat = (struct distributor_stat_t *)dkfw_user_stats_sm_get(proc);
    if(!gp_distributor_stat){
        printf("get stat mem error.\n");
        return -1;
    }
    gp_distributor_stat->proc_id = proc;

    return 0;
}

