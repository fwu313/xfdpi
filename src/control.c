#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>

#include <rte_common.h>
#include <rte_ethdev.h>

#include "cJSON.h"
#include "dpdkframework_ipc.h"
#include "dpdkframework_stats.h"

#include "xfdpi.h"

#define ADD_JSON(k,v) do { \
    snprintf(buff, sizeof(buff), "%lu", v); \
    cJSON_AddItemToObject(json_root, k, cJSON_CreateString(buff)); \
} while(0)

#define ADD_JSON_2(r,k,v) do { \
    snprintf(buff, sizeof(buff), "%lu", v); \
    cJSON_AddItemToObject(r, k, cJSON_CreateString(buff)); \
} while(0)

int pidset = 0;
int to_dkfwstat = 0;
int to_devstat = 0;
int to_cpu = 0;
int to_clearstat = 0;
int to_stat = 0;

static cJSON *make_cpu_json(struct dkfw_stats_t *stat)
{
    cJSON *json_root;
    char buff[128];

    json_root = cJSON_CreateObject();

    ADD_JSON("proc_id", (unsigned long)stat->proc_ind);
    ADD_JSON("elapsed_ms", stat->elapsed_ms);

    ADD_JSON("loops", stat->cpu_stat.loops);
    ADD_JSON("all_tsc", stat->cpu_stat.all_tsc);
    ADD_JSON("timer_tsc", stat->cpu_stat.timer_tsc);
    ADD_JSON("send_tsc", stat->cpu_stat.send_tsc);
    ADD_JSON("rx_tsc", stat->cpu_stat.rx_tsc);
    ADD_JSON("dispatch_tsc", stat->cpu_stat.dispatch_tsc);
    ADD_JSON("shared_tsc", stat->cpu_stat.shared_tsc);

    return json_root;
}

static void print_cpu_json(struct dkfw_stats_t *stat)
{
    cJSON *json_root = make_cpu_json(stat);
    char *jsonstr;

    jsonstr = cJSON_Print(json_root);
    printf("%s\n", jsonstr);

    cJSON_Delete(json_root);
    free(jsonstr);
}

static cJSON *make_inner_stat_json(struct dkfw_stats_t *stat)
{
    cJSON *json_root, *item1;
    char buff[128];
    int i;

    json_root = cJSON_CreateObject();

    ADD_JSON("proc_id", (unsigned long)stat->proc_ind);
    ADD_JSON("elapsed_ms", stat->elapsed_ms);

    ADD_JSON("pkt_in_cnt", stat->env_stat.eth_pkt_in_cnt);
    ADD_JSON("pkt_out_cnt", stat->env_stat.eth_pkt_out_cnt);

    item1 = cJSON_CreateArray();
    for(i=0;i<CORES_PER_TEST_MAX;i++){
        snprintf(buff, sizeof(buff), "%lu", stat->env_stat.core_dispatch_cnt[i]);
        cJSON_AddItemToArray(item1, cJSON_CreateString(buff));
    }
    cJSON_AddItemToObject(json_root, "core_dispatch_cnt", item1);

    item1 = cJSON_CreateObject();
    ADD_JSON_2(item1, "enq_dispatch", stat->env_stat.env_err.enq_dispatch);
    ADD_JSON_2(item1, "eth_send", stat->env_stat.env_err.eth_send);
    cJSON_AddItemToObject(json_root, "env_errs", item1);

    return json_root;
}

static void print_inner_stat_json(struct dkfw_stats_t *stat)
{
    cJSON *json_root = make_inner_stat_json(stat);
    char *jsonstr;

    jsonstr = cJSON_Print(json_root);
    printf("%s\n", jsonstr);

    cJSON_Delete(json_root);
    free(jsonstr);
}

static cJSON *make_devstat_json(struct rte_eth_stats *stat, unsigned long ms)
{
    cJSON *json_root, *item1;
    char buff[128];
    int i;

    json_root = cJSON_CreateObject();

    ADD_JSON("elapsed_ms", ms);

    ADD_JSON("ipackets", stat->ipackets);
    ADD_JSON("opackets", stat->opackets);
    ADD_JSON("ibytes", stat->ibytes);
    ADD_JSON("obytes", stat->obytes);
    ADD_JSON("imissed", stat->imissed);
    ADD_JSON("ierrors", stat->ierrors);
    ADD_JSON("oerrors", stat->oerrors);
    ADD_JSON("rx_nombuf", stat->rx_nombuf);

    item1 = cJSON_CreateArray();
    for(i=0;i<RTE_ETHDEV_QUEUE_STAT_CNTRS;i++){
        snprintf(buff, sizeof(buff), "%lu", stat->q_ipackets[i]);
        cJSON_AddItemToArray(item1, cJSON_CreateString(buff));
    }
    cJSON_AddItemToObject(json_root, "q_ipackets", item1);

    item1 = cJSON_CreateArray();
    for(i=0;i<RTE_ETHDEV_QUEUE_STAT_CNTRS;i++){
        snprintf(buff, sizeof(buff), "%lu", stat->q_opackets[i]);
        cJSON_AddItemToArray(item1, cJSON_CreateString(buff));
    }
    cJSON_AddItemToObject(json_root, "q_opackets", item1);

    item1 = cJSON_CreateArray();
    for(i=0;i<RTE_ETHDEV_QUEUE_STAT_CNTRS;i++){
        snprintf(buff, sizeof(buff), "%lu", stat->q_ibytes[i]);
        cJSON_AddItemToArray(item1, cJSON_CreateString(buff));
    }
    cJSON_AddItemToObject(json_root, "q_ibytes", item1);

    item1 = cJSON_CreateArray();
    for(i=0;i<RTE_ETHDEV_QUEUE_STAT_CNTRS;i++){
        snprintf(buff, sizeof(buff), "%lu", stat->q_obytes[i]);
        cJSON_AddItemToArray(item1, cJSON_CreateString(buff));
    }
    cJSON_AddItemToObject(json_root, "q_obytes", item1);

    item1 = cJSON_CreateArray();
    for(i=0;i<RTE_ETHDEV_QUEUE_STAT_CNTRS;i++){
        snprintf(buff, sizeof(buff), "%lu", stat->q_errors[i]);
        cJSON_AddItemToArray(item1, cJSON_CreateString(buff));
    }
    cJSON_AddItemToObject(json_root, "q_errors", item1);

    return json_root;
}

static void print_devstat_json(struct rte_eth_stats *stat, unsigned long ms)
{
    cJSON *json_root = make_devstat_json(stat, ms);
    char *jsonstr;

    jsonstr = cJSON_Print(json_root);
    printf("%s\n", jsonstr);

    cJSON_Delete(json_root);
    free(jsonstr);
}

static cJSON *make_distributor_json(struct distributor_stat_t *stat)
{
    cJSON *json_root, *item1;
    char buff[128];

    json_root = cJSON_CreateObject();

    ADD_JSON("proc_id", (unsigned long)stat->proc_id);
    ADD_JSON("elapsed_ms", stat->elapsed_ms);
    
    ADD_JSON("hash_add", stat->flow_hash_add_cnt);
    ADD_JSON("hash_remove", stat->flow_hash_remove_cnt);
    
    ADD_JSON("detected", stat->flow_detected_cnt);
    ADD_JSON("detect_fail", stat->flow_detect_fail_cnt);

    ADD_JSON("flow_timeout", stat->flow_timeout_cnt);
    
    ADD_JSON("ignored_pkt", stat->ignored_pkt_cnt);

    ADD_JSON("aging_list_add", stat->aging_list_add_cnt);
    ADD_JSON("aging_list_remove", stat->aging_list_remove_cnt);

    item1 = cJSON_CreateObject();
    ADD_JSON_2(item1, "hash_full", stat->distributor_err.hash_full);
    ADD_JSON_2(item1, "hash_invald", stat->distributor_err.hash_invald);
    cJSON_AddItemToObject(json_root, "distributor_err", item1);

    return json_root;
}

static void print_distributor_json(struct distributor_stat_t *stat)
{
    cJSON *json_root = make_distributor_json(stat);
    char *jsonstr;
    int i;

    jsonstr = cJSON_Print(json_root);
    printf("%s\n", jsonstr);

    cJSON_Delete(json_root);
    free(jsonstr);

    printf("\n");
    for(i=0;i<NDPI_MAX_SUPPORTED_PROTOCOLS;i++){
        if(!stat->protocol_stats[i].detect_pkts){
            continue;
        }
        printf("%8d%16lu%16lu\n", i, stat->protocol_stats[i].detect_pkts, stat->protocol_stats[i].detect_bytes);
    }
}

static int cmd_parse_args(int argc, char **argv)
{
    int opt, cnt = 0;
    char * *argvopt;
    int option_index;

    const char short_options[] = "abjxrscdefig:l:p:k:";
    const struct option long_options[] = {
        {"proc-id", required_argument, NULL, 'p'},

        {"dkfwstat", no_argument, NULL, 'a'},
        {"devstat", no_argument, NULL, 'b'},
        {"cpu", no_argument, NULL, 'c'},
        {"clearstat", no_argument, NULL, 'd'},
        {"stat", no_argument, NULL, 'e'},
        
        { 0, 0, 0, 0},
    };

    argvopt = argv;
    while((opt = getopt_long(argc, argvopt, short_options, long_options, &option_index)) != EOF) {
        switch(opt){
            case 'p':
                pidset = atoi(optarg);
                break;
            case 'a':
                to_dkfwstat = 1;
                cnt++;
                break;
            case 'b':
                to_devstat = 1;
                cnt++;
                break;
            case 'c':
                to_cpu = 1;
                cnt++;
                break;
            case 'd':
                to_clearstat = 1;
                cnt++;
                break;
            case 'e':
                to_stat = 1;
                cnt++;
                break;
            default:
                break;
        }
    }

    if(cnt != 1 || pidset < 0){
        printf("invalid arg.\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret = dkfw_ipc_client_init(argc, argv);
    struct dkfw_stats_t *inner_stat;
    struct distributor_stat_t *user_stat;
    struct dkfw_ipc_msg *msg = NULL;
    
    if(ret < 0){
        printf("dkfw_ipc_client_init client init failed.\n");
        goto exit;
    }

    ret = 0;
    
    if (cmd_parse_args(argc, argv) < 0){
        ret = -1;
        goto exit;
    }

    inner_stat = dkfw_inner_stats_get(pidset);
    if(!inner_stat){
        printf("get inner_stat error.\n");
        ret = -1;
        goto exit;
    }
    
    user_stat = (struct distributor_stat_t *)dkfw_user_stats_sm_get(pidset);
    if(!user_stat){
        printf("get user_stat error.\n");
        ret = -1;
        goto exit;
    }

    msg = dkfw_ipc_client_msg_alloc();
    if(!msg){
        printf("tgipc_msg_alloc failed.\n");
        ret = -1;
        goto exit;
    }

    if(to_dkfwstat){
        print_inner_stat_json(inner_stat);
    }else if(to_devstat){
        struct rte_eth_stats devst;
        if(rte_eth_stats_get(ONLY_PORT_ID, &devst)){
            printf("rte_eth_stats_get err\n");
            ret = -1;
            goto exit;
        }
        print_devstat_json(&devst, inner_stat->elapsed_ms);
    }else if(to_cpu){
        print_cpu_json(inner_stat);
    }else if(to_clearstat){
        msg->msg_type = IPC_CLEAR_STATS;
        if(dkfw_ipc_client_msg_send(msg, pidset) < 0){
            printf("dkfw_ipc_client_msg_send failed.\n");
            ret = -1;
            goto exit;
        }
        if(dkfw_ipc_client_msg_recv(&msg, pidset, 2) < 0){
            printf("dkfw_ipc_client_msg_recv failed.\n");
            ret = -1;
            goto exit;
        }
        if(msg->ipc_msg_str[0]){
            printf("%s", msg->ipc_msg_str);
            printf("\n");
        }
    }else if(to_stat){
        print_distributor_json(user_stat);
    }

exit:

    if(msg){
        dkfw_ipc_client_msg_free(msg);
    }

    if(rte_eal_cleanup() < 0){
        printf("rte_eal_cleanup error.\n");
        ret = -1;
    }
    
    return ret;
}

