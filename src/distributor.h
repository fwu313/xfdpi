#ifndef _TG_DISTRIBUTOR_H
#define _TG_DISTRIBUTOR_H
#include <rte_mbuf.h>
#include "ndpi_main.h"
#include "lbf_list.h"

#define PRIME_VALUE 0xeaad8405

#define APPFLOWS_MAX 1000000

#define APPFLOWS_HASH_LEN 12 // 2 ipv4 + 2 port

#define MAX_INSPECT_PKTS_CNT     16   // LESS than appflow_pkts_cnt !!!

#define APPFLOWS_AGE_LIST_HASH_SIZE (1000 * 100)
#define APPFLOWS_AGE_LIST_DO_PER_MS (APPFLOWS_AGE_LIST_HASH_SIZE / 1000)

#define APPFLOWS_ST_DETECTING   0
#define APPFLOWS_ST_DETECTED    1
#define APPFLOWS_ST_DETECT_FAIL 2
typedef struct _appflow_info_t {
    struct list_head appflow_aging_list;

    uint32_t appflow_st       :3;     // max 7
    uint32_t inspected_pkts_cnt :6;     // max 63
    uint32_t appflow_age      :12;    // max 4095s, n -> 0
    uint16_t buffed_pkts_cnt  :6;     // max 63
    uint32_t spare1           :5;

    uint16_t buffed_bytes_cnt;

    ndpi_protocol detected_ndpi_protocol;
    
    struct ndpi_flow_struct ndpi_flow_sm;

    struct ndpi_id_struct ndpi_flow_sm_src;
    struct ndpi_id_struct ndpi_flow_sm_dst;
} APPFLOW_T;

#define APPFLOW_POS(f) (f - g_appflows)

extern int appflow_idle_timeout;

extern int init_ndpi_base(void);
extern int dpdk_process_packet_one_real(struct rte_mbuf *m);
extern int appflow_aging_do(int nslots);

struct distributor_err_stat_t {
    unsigned long hash_full;
    unsigned long hash_invald;
};

typedef struct _protocol_stats_info_t {
    unsigned long detect_bytes;
    unsigned long detect_pkts;
} PROTOCOL_STATS_T;

struct distributor_stat_t {
    int proc_id;
    unsigned long elapsed_ms;

    unsigned long flow_hash_add_cnt;
    unsigned long flow_hash_remove_cnt;

    unsigned long flow_detected_cnt;
    unsigned long flow_detect_fail_cnt;

    unsigned long flow_timeout_cnt;
    
    unsigned long ignored_pkt_cnt;

    unsigned long aging_list_add_cnt;
    unsigned long aging_list_remove_cnt;

    struct distributor_err_stat_t distributor_err;

    PROTOCOL_STATS_T protocol_stats[NDPI_MAX_SUPPORTED_PROTOCOLS + 4];
};

extern struct distributor_stat_t *gp_distributor_stat;

#define IPC_CLEAR_STATS 0

#endif

