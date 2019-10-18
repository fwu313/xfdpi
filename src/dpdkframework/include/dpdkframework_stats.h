#ifndef _DPDK_FRAMEWORK_STATS_H
#define _DPDK_FRAMEWORK_STATS_H
#include "dpdkframework.h"

struct dkfw_env_err_stat_t {
    unsigned long eth_send;
    unsigned long enq_dispatch;
};

struct dkfw_env_stat_t {

    unsigned long eth_pkt_out_cnt;
    unsigned long eth_pkt_in_cnt;

    unsigned long core_dispatch_cnt[CORES_PER_TEST_MAX];

    struct dkfw_env_err_stat_t env_err;
};

struct dkfw_cpu_stat_t {
    unsigned long loops;
    unsigned long all_tsc;
    unsigned long timer_tsc;
    unsigned long send_tsc;
    unsigned long rx_tsc;
    unsigned long dispatch_tsc;
    unsigned long shared_tsc;
};

struct dkfw_stats_t {
    int proc_ind;
    unsigned long elapsed_ms;
    
    struct dkfw_cpu_stat_t cpu_stat;

    struct dkfw_env_stat_t env_stat;
};

extern struct dkfw_stats_t *g_dpdkframework_stats;
extern struct dkfw_cpu_stat_t *gp_cpu_stat;
extern struct dkfw_env_stat_t *gp_env_stat;

extern int init_dpdkframework_stats(int proc);
extern struct dkfw_stats_t *dkfw_inner_stats_get(int proc_ind);
#endif

