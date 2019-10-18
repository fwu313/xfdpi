#ifndef _DPDK_FRAMEWORK_IPC_H
#define _DPDK_FRAMEWORK_IPC_H
#include "dpdkframework.h"

struct dkfw_ipc_msg {
    int msg_type;
    unsigned long elapsed_ms;
    int msg_id;
    int proc_ind;
    char ipc_msg_str[1];
};

extern int init_ipc_mems(int nb_procs);
extern void *get_inner_stats_shared_mem(int proc_ind);
extern int process_ipc_msg_ring(uint16_t proc_id, dkfw_ipc_msg_process_func_t func);
extern int dkfw_ipc_client_init(int argc, char **argv);
extern struct dkfw_ipc_msg *dkfw_ipc_client_msg_alloc(void);
extern int dkfw_ipc_client_msg_free(struct dkfw_ipc_msg *msg);
extern int dkfw_ipc_client_msg_send(const struct dkfw_ipc_msg *msg, int proc_id);
extern int dkfw_ipc_client_msg_recv(struct dkfw_ipc_msg **msg, int proc_id, int timeout);
extern int dkfw_ipc_server_msg_sendback(struct dkfw_ipc_msg *msg);
#endif

