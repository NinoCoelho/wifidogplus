/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * client_record_queue.c
 * Original Author : chenjunpei@jarxi.com, 2016-7-7.
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
#include "client_record_queue.h"
#include "list.h"


#define MAX_CLIENT_RECORD_COUNT (1 << 13UL)


static LIST_HEAD(client_record_queue);
static pthread_mutex_t client_record_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int client_record_count;


int client_record_queue_init()
{
    /* did not need to do anything now */
    return 0;
}

void client_record_queue_destory()
{
    client_record_queue_node_t      *pos;
    client_record_queue_node_t      *pos_tmp;

    pthread_mutex_lock(&client_record_queue_mutex);
    list_for_each_entry_safe(pos, pos_tmp, &client_record_queue, client_record_queue_node_t, list) {
        list_del(&pos->list);
        client_record_count--;
        careful_free(pos);
    }
    pthread_mutex_unlock(&client_record_queue_mutex);

    return;
}

/* did not need lock, but must using caution */
static client_record_queue_node_t *client_record_queue_find(char *mac, time_t assoc_time)
{
    client_record_queue_node_t      *pos;

    list_for_each_entry(pos, &client_record_queue, client_record_queue_node_t, list) {
        if (!strncasecmp(mac, pos->mac, MAC_ADDR_LEN) && (pos->assoc_time == assoc_time)) {
            return pos;
        }
    }

    return NULL;
}

int client_record_queue_enqueue(char *mac, time_t assoc_time)
{
    client_record_queue_node_t *new_node;

    if (!mac) {
        return -1;
    }

    pthread_mutex_lock(&client_record_queue_mutex);
    if (client_record_count >= MAX_CLIENT_RECORD_COUNT) {
        debug(LOG_ERR, "client_record_count more than max %d", MAX_CLIENT_RECORD_COUNT);
        pthread_mutex_unlock(&client_record_queue_mutex);
        return -1;
    }

    if (client_record_queue_find(mac, assoc_time)) {
        pthread_mutex_unlock(&client_record_queue_mutex);
        return 1;
    }

    new_node = (client_record_queue_node_t *)malloc(sizeof(client_record_queue_node_t));
    if (!new_node) {
        debug(LOG_ERR, "fail to get memory");
        pthread_mutex_unlock(&client_record_queue_mutex);
        return -1;
    }

    memset(new_node, 0, sizeof(client_record_queue_node_t));
    memcpy(new_node->mac, mac, MAC_ADDR_LEN);
    new_node->assoc_time = assoc_time;
    list_add_tail(&new_node->list, &client_record_queue);
    client_record_count++;
    pthread_mutex_unlock(&client_record_queue_mutex);

    return 0;
}

int client_record_queue_dequeue(client_record_queue_node_t *buf)
{
    client_record_queue_node_t      *ret_node;

    if (!buf) {
        return -1;
    }

    pthread_mutex_lock(&client_record_queue_mutex);
    ret_node = list_first_entry(&client_record_queue, client_record_queue_node_t, list);
    if (!ret_node) {
        pthread_mutex_unlock(&client_record_queue_mutex);
        return -1;
    }

    memcpy(buf, ret_node, sizeof(client_record_queue_node_t));
    list_del(&ret_node->list);
    client_record_count--;
    pthread_mutex_unlock(&client_record_queue_mutex);

    if (ret_node) {
        free(ret_node);
    }

    return 0;
}

int client_record_queue_delete(char *mac, time_t assoc_time)
{
    client_record_queue_node_t      *ret_node;

    pthread_mutex_lock(&client_record_queue_mutex);
    ret_node = client_record_queue_find(mac, assoc_time);
    if (!ret_node) {
        pthread_mutex_unlock(&client_record_queue_mutex);
        debug(LOG_ERR, "can not find %s", mac);
        return -1;
    }

    list_del(&ret_node->list);
    client_record_count--;
    pthread_mutex_unlock(&client_record_queue_mutex);

    if (ret_node) {
        free(ret_node);
    }

    return 0;
}

int client_record_queue_peek_last(client_record_queue_node_t *buf)
{
    client_record_queue_node_t      *ret_node;

    if (!buf) {
        return -1;
    }

    pthread_mutex_lock(&client_record_queue_mutex);
    ret_node = list_last_entry(&client_record_queue, client_record_queue_node_t, list);
    if (!ret_node) {
        pthread_mutex_unlock(&client_record_queue_mutex);
        debug(LOG_ERR, "can not get last mac");
        return -1;
    }
    pthread_mutex_unlock(&client_record_queue_mutex);

    memcpy(buf, ret_node, sizeof(client_record_queue_node_t));

    return 0;
}

void client_record_queue_show_all()
{
    client_record_queue_node_t      *pos;
    int i = 0;

    printf("%s: print all mac in client_record_queue\n", __FUNCTION__);
    pthread_mutex_lock(&client_record_queue_mutex);
    list_for_each_entry(pos, &client_record_queue, client_record_queue_node_t, list) {
        printf("%d: %s %d\n", ++i, pos->mac, pos->assoc_time);
    }
    printf("total %u\n", client_record_count);
    pthread_mutex_unlock(&client_record_queue_mutex);
}

void client_record_queue_traverse(_IN CLIENT_RECORD_TRAVERSE_FUNC func, _IN void *arg)
{
    client_record_queue_node_t      *pos;
    client_record_queue_node_t      *pos_tmp;

    pthread_mutex_lock(&client_record_queue_mutex);
    list_for_each_entry_safe(pos, pos_tmp, &client_record_queue, client_record_queue_node_t, list) {
        if (func) {
            (void)func(pos, arg);
        }
    }
    pthread_mutex_unlock(&client_record_queue_mutex);
}

