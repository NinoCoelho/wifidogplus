/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * fw_backup.c
 * Original Author : cjpthree@126.com, 2015-8-6.
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


#define FW_BACKUP_FILE "/tmp/wifidog_fw_backup"


static int fw_backup_restore_mac(char *mac, char *ip, int auth, unsigned int fw_state)
{
	s_config *config = config_get_config();
    time_t current_time = time(NULL);
    client_t client;

    if (!is_mac_valid(mac) || !is_ip_valid(ip)) {
        debug(LOG_ERR, "%s: data invalid", __FUNCTION__);
        return -1;
    }

    debug(LOG_DEBUG, "restore mac %s ip %s auth %d fw_state %u", mac, ip, auth, fw_state);
    if (client_list_get_client(mac, &client) == RET_SUCCESS) {
        if (client.auth >= auth) {
            return 0;       /* this client in client list yet, did not do restore */
        }
    }
    (void)client_list_add(mac);
    (void)client_list_set_ip(mac, ip);
    (void)client_list_set_auth(mac, (int)auth);
    if (auth < CLIENT_CONFIG) {
        (void)iptables_fw_untracked_mac(mac);   /* cannot do it first. untracked first, because can not confirm that whether the ip in iptables or not now */
        (void)iptables_fw_tracked_mac(mac);
    }
    if (config ->allow_first){
    	if (auth >= CLIENT_CHAOS || CLIENT_ALLOWED == fw_state)
		{
	        (void)iptables_fw_deny_mac(mac);        /* deny first, because can not confirm that whether the mac in iptables or not now */
	        (void)iptables_fw_allow_mac(mac);
	        if (auth < CLIENT_CONFIG) {
	            (void)client_list_set_last_updated(mac, current_time);
	        }
	    }
    }
    else{
    	if (auth > CLIENT_CHAOS || CLIENT_ALLOWED == fw_state)
	    {
	        (void)iptables_fw_deny_mac(mac);        /* deny first, because can not confirm that whether the mac in iptables or not now */
	        (void)iptables_fw_allow_mac(mac);
	        if (auth < CLIENT_CONFIG) {
	            (void)client_list_set_last_updated(mac, current_time);
	        }
	    }
    }

    return 0;
}

int fw_backup_from_client_list()
{
    dlist_head_t restore_list = DLIST_HEAD_INIT(restore_list);
    client_hold_t *pos;
    client_list_hold_t hold;

    hold.head = &restore_list;
    hold.func = NULL;
    hold.args = NULL;
    if (client_list_traverse((CLIENT_LIST_TRAVERSE_FUNC)client_list_hold, &hold)) {
        client_list_destory_hold(&hold);
        debug(LOG_ERR, "fail to hold fillwall");
        return -1;
    }

    dlist_for_each_entry(pos, &restore_list, client_hold_t, list) {
        (void)fw_backup_restore_mac(pos->client.mac, pos->client.ip,
            pos->client.auth, pos->client.fw_state);
    }

    client_list_destory_hold(&hold);

    return 0;
}

int fw_backup_from_file()
{
    FILE *file;
    char mac[MAC_ADDR_LEN] = {0};
    char ip[MAX_IPV4_LEN] = {0};
    char auth[32] = {0};
    char fw_state[32] = {0};
    int ret;

    if (!(file = fopen(FW_BACKUP_FILE, "r"))) {
        debug(LOG_INFO, "can not open %s, it may be not exist", FW_BACKUP_FILE);
        return -1;
    }

    while (!feof(file)) {
        memset(mac, 0, MAC_ADDR_LEN);
        memset(ip, 0, MAX_IPV4_LEN);
        memset(auth, 0, sizeof(auth) / sizeof(auth[0]));
        memset(fw_state, 0, sizeof(fw_state) / sizeof(fw_state[0]));
        ret = fscanf(file, "%s %s %s %s\n", mac, ip, auth, fw_state);
        if (ret != 4) {
            break;
        }
        (void)fw_backup_restore_mac(mac, ip, atoi(auth), atoi(fw_state));
    }

    fclose(file);
    return 0;
}

static int fw_backup_store_mac(dlist_head_t *head, FILE *file)
{
    int ret;
    client_hold_t *pos;

    dlist_for_each_entry(pos, head, client_hold_t, list) {
        ret = fprintf(file, "%s %s %d %u\n",
            pos->client.mac, pos->client.ip, pos->client.auth, pos->client.fw_state);
        if (ret == -1) {
            debug(LOG_ERR, "fail to backup mac %s", pos->client.mac);
            return -1;
        }
    }

    return 0;
}

int fw_backup_refresh()
{
    FILE *file;
    int ret;
    char mac[MAC_ADDR_LEN] = {0};
    dlist_head_t refresh_list = DLIST_HEAD_INIT(refresh_list);
    client_list_hold_t hold;

    if (!(file = fopen(FW_BACKUP_FILE, "w+"))) {
        debug(LOG_ERR, "fail to open %s", FW_BACKUP_FILE);
        return -1;
    }

    hold.head = &refresh_list;
    hold.func = NULL;
    hold.args = NULL;
    if (client_list_traverse((CLIENT_LIST_TRAVERSE_FUNC)client_list_hold, &hold)) {
        fclose(file);
        client_list_destory_hold(&hold);
        debug(LOG_ERR, "fail to hold fillwall");
        return -1;
    }

    if (fw_backup_store_mac(&refresh_list, file)) {
        fclose(file);
        client_list_destory_hold(&hold);
        debug(LOG_ERR, "fail to backup fillwall");
        return -1;
    }

    fclose(file);
    client_list_destory_hold(&hold);
    return 0;
}

