/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * qos.c
 * Original Author : cjpthree@126.com, 2015-10-26.
 *
 * Description
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "client_access.h"
#include "client_list.h"
#include "firewall.h"
#include "get_client.h"
#include "siso_queue.h"
#include "list.h"
#include "fw_backup.h"
#include "fw_iptables.h"

#define MAX_QOS_SEQ MAX_CLIENT_NUM

static char qos_seq_bank[MAX_QOS_SEQ] ={0};

static unsigned int qos_get_available_seq(const char *mac)
{
    int i;

    for (i = 0; i < MAX_QOS_SEQ; i++) {
        if (0 == qos_seq_bank[i]) {
            return i + 1;
        }
    }
    
    return 0;
}

static void qos_set_seq(unsigned int seq)
{
    qos_seq_bank[seq - 1] = 1;
}

static void qos_clear_seq(unsigned int seq)
{
    qos_seq_bank[seq - 1] = 0;
}

static int qos_build_command(char *buf, const char *ip, int uplink_limit, int downlink_limit, unsigned int seq, int enable)
{
    sprintf(buf, "qos-set.sh '2,%s,%s,0,%d,%d,%d,1,%d'", ip, ip, uplink_limit, downlink_limit, enable, seq);
    return 0;
}

static int qos_clear(const char *mac, const char *ip, int uplink_limit, int downlink_limit, unsigned int seq)
{
    char cmd[MAX_BUF] = {0};
    
    if (qos_build_command(cmd, ip, uplink_limit, downlink_limit, seq, 0)) {
        debug(LOG_ERR, "can not build qos command for %s", ip);
        return -1;
    }
    execute_cmd(cmd, NULL);

    client_list_set_uplink_limit(mac, 0);
    client_list_set_downlink_limit(mac, 0);
    client_list_clear_qos_seq(mac);
    qos_clear_seq(seq);
    
    return 0;
}

static int qos_set(const char *mac, const char *ip, int uplink_limit, int downlink_limit, unsigned int seq)
{
    char cmd[MAX_BUF] = {0};
    
    if (qos_build_command(cmd, ip, uplink_limit, downlink_limit, seq, 1)) {
        debug(LOG_ERR, "can not build qos command for %s", ip);
        return -1;
    }
    execute_cmd(cmd, NULL);

    client_list_set_uplink_limit(mac, uplink_limit);
    client_list_set_downlink_limit(mac, downlink_limit);
    client_list_set_qos_seq(mac, seq);
    qos_set_seq(seq);
    
    return 0;
}

int do_qos(const char *mac)
{
    unsigned int uplink = 0;
    unsigned int downlink = 0;
    client_t client;
    unsigned int seq = 0;

    if (!is_mac_valid(mac)) {
        return -1;
    }

    debug(LOG_DEBUG, "doing qos for %s", mac);

    if (!(config_get_config()->qosEnable)) {
        return 0;
    }

    if (client_list_get_client(mac, &client) != RET_SUCCESS) {
        return -1;
    }

    /* caculate speed */
    if (client.auth >= CLIENT_CONFIG) {
        if (client.counters.uplink_limit == 0 && client.counters.downlink_limit == 0) {
            return 0;
        }
    } else if (client.auth >= CLIENT_VIP) {
        uplink = config_get_config()->uplinkVip;
        downlink = config_get_config()->downlinkVip;
    } else if (client.auth >= CLIENT_CHAOS) {
        uplink = config_get_config()->uplinkCommon;
        downlink = config_get_config()->downlinkCommon;
    } else {
        if (client.counters.uplink_limit == 0 && client.counters.downlink_limit == 0) {
            return 0;
        }
    }

    if (client.counters.uplink_limit != uplink || client.counters.downlink_limit != downlink) {
        if (client.counters.uplink_limit != 0 || client.counters.downlink_limit != 0) {
            (void)qos_clear(mac, client.ip, client.counters.uplink_limit, 
                client.counters.downlink_limit, client.counters.qos_seq);
        }

        if (uplink != 0 && downlink != 0) { /* can not limit 0 kbps */
            seq = qos_get_available_seq(mac);
            if (0 == seq) {
                debug(LOG_ERR, "can not find a available sequence number for %s", mac);
                return -1;
            }
            if (qos_set(mac, client.ip, uplink, downlink, seq) != RET_SUCCESS) {
                debug(LOG_ERR, "can not set qos for %s", mac);
                return -1;
            }
        }
    }

    return 0;
}

