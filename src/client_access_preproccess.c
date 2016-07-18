/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * client_access_preproccess.c
 * Original Author : cjpthree@126.com, 2015-7-6.
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

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "client_access.h"
#include "client_list.h"
#include "firewall.h"
#include "get_client.h"
#include "client_access_preproccess.h"
#include "client_access_queue.h"
#include "client_record_queue.h"


sem_t sem_client_access_preproccess;


int thread_client_access_preproccess(char *arg)
{
    unsigned char mac[MAC_ADDR_LEN];
    int ret;
    unsigned int auth;
    unsigned int fw_state;
    time_t current_time;
    time_t last_updated;
    client_t client;    
	s_config *config = config_get_config();

    if (client_access_queue_init()) {
        debug(LOG_ERR, "fail to init client access queue!");
        return -1;
    }

#ifdef HUOBAN_APP03
    if (client_record_queue_init()) {
        debug(LOG_ERR, "fail to init client record queue!");
        return -1;
    }
#endif

    while(1)
    {
        memset(mac, 0, MAC_ADDR_LEN);
        sem_wait(&sem_client_access_get_mac);
        if (siso_queue_get_mac(mac)) {
            debug(LOG_WARNING, "get mac from queue error");
            continue;
        }

        if (!is_mac_valid(mac)) {
            debug(LOG_WARNING, "mac invalid");
            continue;
        }
        current_time = time(NULL);

#ifdef HUOBAN_APP03
        ret = client_record_queue_enqueue(mac, current_time);
        if (ret == 1) {
            debug(LOG_DEBUG, "mac %s had existed in client record queue", mac);
            continue;
        } else if (ret == -1) {
            debug(LOG_DEBUG, "fail to enqueue mac %s to client record queue", mac);
            continue;
        }
        continue;
#endif

        memset((void *)&client, 0, sizeof(client_t));
        if (RET_SUCCESS == client_list_get_client(mac, &client)) {
            if (config->wd_reAssoc_reAuth) {
                if (client.auth < CLIENT_CONFIG) {
                    (void)iptables_fw_deny_mac(mac);
                    (void)client_list_set_auth(mac, CLIENT_CHAOS);
                }
                (void)client_list_set_last_updated(mac, current_time);
                continue;
            }

            if (client.auth > CLIENT_CHAOS) {
                debug(LOG_DEBUG, "mac %s had authenticated", mac);
                (void)iptables_fw_allow_mac(mac);
                if (client.auth < CLIENT_CONFIG) {
                    (void)iptables_fw_tracked_mac(mac);
                }
                (void)client_list_set_last_updated(mac, current_time);
                continue;
            }

#if ANTI_DOS
            if (current_time - client.counters.last_updated < ANTI_DOS_TIME) {
                unsigned int dos_count = 0;
                (void)client_list_increase_dos_count(mac);
                (void)client_list_get_dos_count(mac, &dos_count);
                if (dos_count > ANTI_DOS_LIMIT) {
                    debug(LOG_INFO, "[%s] Anti DoS, ignore this request", mac);
                    continue;
                }
            } else {
                (void)client_list_clear_dos_count(mac);
                (void)client_list_set_last_updated(mac, current_time);
            }
#endif
        } else {
            (void)client_list_add(mac);
        }
        
#if LOCAL_AUTH
        if (config->wd_reAssoc_reAuth) {
            if (client.auth < CLIENT_CONFIG) {
                (void)iptables_fw_deny_mac(mac);
                (void)client_list_set_auth(mac, CLIENT_CHAOS);
            }
            (void)client_list_set_last_updated(mac, current_time);
        }
        continue;
#endif

        ret = client_access_queue_enqueue(mac);
        if (ret == 1) {
            debug(LOG_DEBUG, "mac %s had existed in client access queue", mac);
            continue;
        } else if (ret == -1) {
            debug(LOG_DEBUG, "fail to enqueue mac %s to client access queue", mac);
            continue;
        }

        sem_post(&sem_client_access_preproccess);
        (void)client_list_set_last_updated(mac, current_time);
#if ALLOW_FIRST_WIRELESS
        (void)iptables_fw_allow_mac(mac);
#endif
    }

    client_access_queue_destory();
#ifdef HUOBAN_APP03
    client_record_queue_destory();
#endif
    return 0;
}

