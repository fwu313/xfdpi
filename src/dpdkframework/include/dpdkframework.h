#ifndef _DPDK_FRAMEWORK_H
#define _DPDK_FRAMEWORK_H
#include <rte_common.h>
#include <rte_mbuf.h>

#define ONLY_PORT_ID 0
#define CORES_PER_TEST_MAX 40

#define NETCARD_TYPE_IXGBE 0
#define NETCARD_TYPE_I40E  1

typedef struct _tg_config_t {
    int proc_all_cnt;
    int proc_id;
    int lcore_id;
    int socket_id;

    int eth_port_socket_id;

    int numa;
    int use_prefetch;
    
    char *cores;

    int is_dispatch_core;
    char *dispatch_cores;
    int dispatch_all_cnt;

    int share_core;

    int nic_type;

    int nic_tx_desc;
    int nic_rx_desc;

    unsigned char ethmac[6];
} DPDKFRAMEWORK_CONFIG_T;


#define IS_APP_CORE (!g_dpdkframework_config.is_dispatch_core)
#define IS_DISPATCH_CORE (g_dpdkframework_config.is_dispatch_core)

#define DISPATCH_CORES_NUM (g_dpdkframework_config.dispatch_all_cnt)
#define DISPATCH_THREADS_NUM (g_dpdkframework_config.dispatch_all_cnt ? g_dpdkframework_config.dispatch_all_cnt : g_dpdkframework_config.proc_all_cnt)
#define ALL_CORES_NUM (g_dpdkframework_config.proc_all_cnt + g_dpdkframework_config.dispatch_all_cnt)

extern DPDKFRAMEWORK_CONFIG_T g_dpdkframework_config;

extern unsigned int dkfw_elapsed_ms;

typedef void (*loop_ms_fn_t)(uint32_t *ms_cnt_0, uint32_t *ms_cnt_1, uint32_t ms_diff);
typedef void (*dkfw_ipc_msg_process_func_t)(void *msg, int proc_ind);

typedef void (*loop_send_fn_t)(int *busy, uint64_t tsc);
typedef void (*loop_eth_rx_fn_t)(struct rte_mbuf *m);
typedef void (*loop_dispatch_q_rx_fn_t)(struct rte_mbuf *m);

struct loop_arg_t {
    int loop_proc_id;
    loop_ms_fn_t loop_ms_do;
    loop_send_fn_t loop_send;
    
    loop_eth_rx_fn_t loop_eth_rx;
    int loop_eth_rx_disabled;
    
    loop_dispatch_q_rx_fn_t loop_dispatch_rx;
    int loop_dispatch_rx_disabled;
    
    dkfw_ipc_msg_process_func_t process_ipc_msg;
};

extern int dkfw_my_proc_ind(void);
extern int dkfw_init(int argc, char **argv);
extern void dkfw_start_loop(struct loop_arg_t *loop_arg);
extern int dkfw_send_pkt_to_dispatchQ(struct rte_mbuf *m, int dst_proc_ind);
extern void *dkfw_user_stats_sm_get(int proc_ind);
#endif

