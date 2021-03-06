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
#include "wifiga_ubus_client.h"
#include "siso_queue.h"


sem_t sem_client_access_preproccess;


int thread_client_access_preproccess(char *arg)
{
    client_node_t node;
    unsigned char *mac = node.mac;
    int ret;
    unsigned int auth;
    unsigned int fw_state;
    time_t current_time;
    time_t last_updated;
    client_t client;
	s_config *config = config_get_config();

    while(1)
    {
        memset(&node, 0, sizeof(client_node_t));
        sem_wait(&sem_client_access_get_mac);
        if (get_client_dequeue(&node)) {
            debug(LOG_WARNING, "get mac from queue error");
            continue;
        }

        if (!is_mac_valid(mac)) {
            debug(LOG_WARNING, "mac invalid");
            continue;
        }
        current_time = time(NULL);

        memset((void *)&client, 0, sizeof(client_t));
        if (RET_SUCCESS == client_list_get_client(mac, &client)) {
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
            client_list_get_client(mac, &client);
        }

        if (0 != node.rssi) {
            (void)client_list_set_rssi(mac, node.rssi);
        }

        if (config->wd_reAssoc_reAuth) {
            if (client.auth < CLIENT_CONFIG) {
                (void)iptables_fw_deny_mac(mac);
                (void)client_list_set_auth(mac, CLIENT_CHAOS);
            }
            (void)client_list_set_last_updated(mac, current_time);
        } else if (client.auth > CLIENT_CHAOS) {
            debug(LOG_DEBUG, "mac %s had authenticated", mac);
            (void)iptables_fw_allow_mac(mac);
            if (client.auth < CLIENT_CONFIG) {
                (void)iptables_fw_tracked_mac(mac);
            }
            (void)client_list_set_last_updated(mac, current_time);
        }

        if (config->wd_auth_mode == AUTH_LOCAL_APPCTL) {
            ret = client_record_queue_enqueue(mac, current_time);
            if (ret == 1) {
                debug(LOG_DEBUG, "mac %s had existed in client record queue", mac);
            } else if (ret == -1) {
                debug(LOG_DEBUG, "fail to enqueue mac %s to client record queue", mac);
            }
            continue;
        } else if (config->wd_auth_mode == AUTH_SERVER_XIECHENG && client.auth <= CLIENT_CHAOS) {
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
            if (config ->allow_first)
            	(void)iptables_fw_allow_mac(mac);
        }
    }

    return 0;
}

