#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_log.h>
#include <rte_memory.h>
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
#include <rte_jhash.h>

#include "dpdkframework.h"
#include "dpdkframework_ipc.h"
#include "xfdpi.h"

int get_pkt_core_and_intf(struct rte_mbuf *m, int *coreid)
{
    char *dpdkdat = rte_pktmbuf_mtod(m, char *);
    struct ether_hdr *ethhdr;
    struct ipv4_hdr *ipv4hdr;
    struct tcp_hdr *tcp_hdr;

    if(g_dpdkframework_config.proc_all_cnt == 1){
        *coreid = 0;
        return 0;
    }

    ethhdr = (struct ether_hdr *)dpdkdat;
    
    if(likely(ntohs(ethhdr->ether_type) == ETHER_TYPE_IPv4)){
        ipv4hdr = (struct ipv4_hdr *)(dpdkdat + ETHER_HDR_LEN);
        if(ipv4hdr->next_proto_id == IPPROTO_TCP){
            tcp_hdr = (struct tcp_hdr *)((char *)ipv4hdr + (ipv4hdr->version_ihl & 0x0f) * 4);

            if(htonl(ipv4hdr->src_addr) < htonl(ipv4hdr->dst_addr)){
                *coreid = rte_jhash_3words(htonl(ipv4hdr->src_addr), htonl(ipv4hdr->dst_addr), ntohs(tcp_hdr->src_port) + ntohs(tcp_hdr->dst_port), PRIME_VALUE) % g_dpdkframework_config.proc_all_cnt;
            }else{
                *coreid = rte_jhash_3words(htonl(ipv4hdr->dst_addr), htonl(ipv4hdr->src_addr), ntohs(tcp_hdr->src_port) + ntohs(tcp_hdr->dst_port), PRIME_VALUE) % g_dpdkframework_config.proc_all_cnt;
            }
        }else{
            return -1;
        }
    }else{
        return -1;
    }

    return 0;
}

void eth_rx_standalone(struct rte_mbuf *m)
{
    int core_id;

    if(unlikely(get_pkt_core_and_intf(m, &core_id) < 0)){
        gp_distributor_stat->ignored_pkt_cnt++;
        rte_pktmbuf_free(m);
        return;
    }

    if(core_id == g_dpdkframework_config.proc_id){
        dpdk_process_packet_one_real(m);
    }else{
        if(dkfw_send_pkt_to_dispatchQ(m, core_id) < 0){
            rte_pktmbuf_free(m);
        }
    }
}

static void ms_timer_do_distributor(uint32_t *ms_cnt_0, uint32_t *ms_cnt_1, uint32_t ms_diff)
{
    gp_distributor_stat->elapsed_ms = dkfw_elapsed_ms;
    
    if(IS_APP_CORE){
        appflow_aging_do(APPFLOWS_AGE_LIST_DO_PER_MS);
    }
}

static void process_ipc_msg(void *msg, int proc_ind)
{
    struct dkfw_ipc_msg *ipcmsg = (struct dkfw_ipc_msg *)msg;

    switch(ipcmsg->msg_type){
        case IPC_CLEAR_STATS:
            sprintf(ipcmsg->ipc_msg_str, "clear stats OK.");
            break;
        default:
            ipcmsg->ipc_msg_str[0] = 0;
            break;
    }

    dkfw_ipc_server_msg_sendback(ipcmsg);
}

int main(int argc, char **argv)
{
    struct loop_arg_t loop_arg;
    memset(&loop_arg, 0, sizeof(loop_arg));

    if(dkfw_init(argc, argv) < 0){
        return -1;
    }

    if(init_ndpi_base() < 0){
        return -1;
    }

    loop_arg.loop_ms_do = ms_timer_do_distributor;
    loop_arg.process_ipc_msg = process_ipc_msg;
    if(DISPATCH_CORES_NUM){
        if(IS_APP_CORE){
            // loop_arg.loop_dispatch_rx = dispatch_q_rx_apponly_distributor;
        }else{
            // loop_arg.loop_eth_rx = eth_rx_dispatch_core_distributor;
        }
    }else{
        loop_arg.loop_eth_rx = eth_rx_standalone;
        // loop_arg.loop_dispatch_rx = dispatch_q_rx_stdalone_distributor;
    }

    dkfw_start_loop(&loop_arg);

    return 0;
}

