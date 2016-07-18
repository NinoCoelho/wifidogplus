/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * client_access_queue.c
 * Original Author : cjpthree@126.com, 2015-7-11.
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
#include "list.h"


typedef struct mac_node_s {
    list_head_t     list;
    char            mac[MAC_ADDR_LEN];
} mac_node_t;


static LIST_HEAD(client_access_queue);
static pthread_mutex_t client_access_queue_mutex = PTHREAD_MUTEX_INITIALIZER;


int client_access_queue_init()
{
    /* did not need to do anything now */
    return 0;
}

void client_access_queue_destory()
{
    mac_node_t      *pos;
    mac_node_t      *pos_tmp;

    pthread_mutex_lock(&client_access_queue_mutex);
    list_for_each_entry_safe(pos, pos_tmp, &client_access_queue, mac_node_t, list) {
        list_del(&pos->list);
        careful_free(pos);
    }
    pthread_mutex_unlock(&client_access_queue_mutex);

    return;
}

/* did not need lock, but must using caution */
static mac_node_t *client_access_queue_find(char *mac)
{
    mac_node_t      *pos;

    list_for_each_entry(pos, &client_access_queue, mac_node_t, list) {
        if (!strncasecmp(mac, pos->mac, MAC_ADDR_LEN)) {
            return pos;
        }
    }

    return NULL;
}

int client_access_queue_enqueue(char *mac)
{
    mac_node_t *new_node;

    if (!mac) {
        return -1;
    }

    pthread_mutex_lock(&client_access_queue_mutex);
    if (client_access_queue_find(mac)) {
        pthread_mutex_unlock(&client_access_queue_mutex);
        return 1;
    }

    new_node = (mac_node_t *)malloc(sizeof(mac_node_t));
    if (!new_node) {
        debug(LOG_ERR, "fail to get memory");
        pthread_mutex_unlock(&client_access_queue_mutex);
        return -1;
    }

    memset(new_node, 0, sizeof(mac_node_t));
    memcpy(new_node->mac, mac, MAC_ADDR_LEN);
    list_add_tail(&new_node->list, &client_access_queue);
    pthread_mutex_unlock(&client_access_queue_mutex);

    return 0;
}

int client_access_queue_dequeue(char *buf)
{
    mac_node_t      *ret_node;

    if (!buf) {
        return -1;
    }

    pthread_mutex_lock(&client_access_queue_mutex);
    ret_node = list_first_entry(&client_access_queue, mac_node_t, list);
    if (!ret_node) {
        pthread_mutex_unlock(&client_access_queue_mutex);
        return -1;
    }

    memcpy(buf, ret_node->mac, MAC_ADDR_LEN);

    list_del(&ret_node->list);
    pthread_mutex_unlock(&client_access_queue_mutex);

    if (ret_node) {
        free(ret_node);
    }

    return 0;
}

int client_access_queue_delete(char *mac)
{
    mac_node_t      *ret_node;

    pthread_mutex_lock(&client_access_queue_mutex);
    ret_node = client_access_queue_find(mac);
    if (!ret_node) {
        pthread_mutex_unlock(&client_access_queue_mutex);
        debug(LOG_ERR, "can not find %s", mac);
        return -1;
    }

    list_del(&ret_node->list);
    pthread_mutex_unlock(&client_access_queue_mutex);

    if (ret_node) {
        free(ret_node);
    }

    return 0;
}

int client_access_queue_peek_last(char *buf)
{
    mac_node_t      *ret_node;

    if (!buf) {
        return -1;
    }

    pthread_mutex_lock(&client_access_queue_mutex);
    ret_node = list_last_entry(&client_access_queue, mac_node_t, list);
    if (!ret_node) {
        pthread_mutex_unlock(&client_access_queue_mutex);
        debug(LOG_ERR, "can not get last mac");
        return -1;
    }
    pthread_mutex_unlock(&client_access_queue_mutex);

    memcpy(buf, ret_node->mac, MAC_ADDR_LEN);

    return 0;
}

void client_access_queue_show_all()
{
    mac_node_t      *pos;
    int i = 0;

    printf("%s: print all mac in client_access_queue\n", __FUNCTION__);
    pthread_mutex_lock(&client_access_queue_mutex);
    list_for_each_entry(pos, &client_access_queue, mac_node_t, list) {
        printf("%d: %s\n", ++i, pos->mac);
    }
    pthread_mutex_unlock(&client_access_queue_mutex);
    printf("\n");
}

