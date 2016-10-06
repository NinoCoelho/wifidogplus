/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * click_record_queue.c
 * Original Author : chenjunpei@jarxi.com, 2016-7-11.
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
#include "click_record_queue.h"
#include "list.h"


#define MAX_CLICK_RECORD_COUNT (1 << 13UL)


static DLIST_HEAD(click_record_queue);
static pthread_mutex_t click_record_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int click_record_count;


int click_record_queue_init()
{
    /* did not need to do anything now */
    return 0;
}

void click_record_queue_destory()
{
    click_record_queue_node_t      *pos;
    click_record_queue_node_t      *pos_tmp;

    pthread_mutex_lock(&click_record_queue_mutex);
    dlist_for_each_entry_safe(pos, pos_tmp, &click_record_queue, click_record_queue_node_t, dlist) {
        dlist_del(&pos->dlist);
        click_record_count--;
        careful_free(pos);
    }
    pthread_mutex_unlock(&click_record_queue_mutex);

    return;
}

/* did not need lock, but must using caution */
static click_record_queue_node_t *click_record_queue_find(char *appid, time_t click_time)
{
    click_record_queue_node_t      *pos;

    dlist_for_each_entry(pos, &click_record_queue, click_record_queue_node_t, dlist) {
        if (!strncasecmp(appid, pos->appid, APPID_LEN) && (pos->click_time == click_time)) {
            return pos;
        }
    }

    return NULL;
}

int click_record_queue_enqueue(char *appid, char *mac, int type, time_t click_time)
{
    click_record_queue_node_t *new_node;

    if (!appid || !mac) {
        return -1;
    }

    pthread_mutex_lock(&click_record_queue_mutex);
    if (click_record_count >= MAX_CLICK_RECORD_COUNT) {
        debug(LOG_ERR, "click_record_count more than max %d", MAX_CLICK_RECORD_COUNT);
        pthread_mutex_unlock(&click_record_queue_mutex);
        return -1;
    }

    if (click_record_queue_find(appid, click_time)) {
        pthread_mutex_unlock(&click_record_queue_mutex);
        return 1;
    }

    new_node = (click_record_queue_node_t *)malloc(sizeof(click_record_queue_node_t));
    if (!new_node) {
        debug(LOG_ERR, "fail to get memory");
        pthread_mutex_unlock(&click_record_queue_mutex);
        return -1;
    }

    memset(new_node, 0, sizeof(click_record_queue_node_t));
    memcpy(new_node->appid, appid, APPID_LEN);
    memcpy(new_node->mac, mac, MAC_ADDR_LEN);
    new_node->type = type;
    new_node->click_time = click_time;
    dlist_add_tail(&new_node->dlist, &click_record_queue);
    click_record_count++;
    pthread_mutex_unlock(&click_record_queue_mutex);

    return 0;
}

int click_record_queue_dequeue(click_record_queue_node_t *buf)
{
    click_record_queue_node_t      *ret_node;

    if (!buf) {
        return -1;
    }

    pthread_mutex_lock(&click_record_queue_mutex);
    ret_node = dlist_first_entry(&click_record_queue, click_record_queue_node_t, dlist);
    if (!ret_node) {
        pthread_mutex_unlock(&click_record_queue_mutex);
        return -1;
    }

    memcpy(buf, ret_node, sizeof(click_record_queue_node_t));
    dlist_del(&ret_node->dlist);
    click_record_count--;
    pthread_mutex_unlock(&click_record_queue_mutex);

    if (ret_node) {
        free(ret_node);
    }

    return 0;
}

int click_record_queue_peek_last(click_record_queue_node_t *buf)
{
    click_record_queue_node_t      *ret_node;

    if (!buf) {
        return -1;
    }

    pthread_mutex_lock(&click_record_queue_mutex);
    ret_node = dlist_last_entry(&click_record_queue, click_record_queue_node_t, dlist);
    if (!ret_node) {
        pthread_mutex_unlock(&click_record_queue_mutex);
        debug(LOG_ERR, "can not get last mac");
        return -1;
    }
    pthread_mutex_unlock(&click_record_queue_mutex);

    memcpy(buf, ret_node, sizeof(click_record_queue_node_t));

    return 0;
}

void click_record_queue_show_all()
{
    click_record_queue_node_t      *pos;
    int i = 0;

    printf("%s: print all mac in click_record_queue\n", __FUNCTION__);
    pthread_mutex_lock(&click_record_queue_mutex);
    dlist_for_each_entry(pos, &click_record_queue, click_record_queue_node_t, dlist) {
        printf("%d: %s %s %d %u\n", ++i, pos->appid, pos->mac, pos->type, pos->click_time);
    }
    printf("total %u\n", click_record_count);
    pthread_mutex_unlock(&click_record_queue_mutex);
}

void click_record_queue_traverse(_IN CLICK_RECORD_TRAVERSE_FUNC func, _IN void *arg)
{
    click_record_queue_node_t      *pos;
    click_record_queue_node_t      *pos_tmp;

    pthread_mutex_lock(&click_record_queue_mutex);
    dlist_for_each_entry_safe(pos, pos_tmp, &click_record_queue, click_record_queue_node_t, dlist) {
        if (func) {
            (void)func(pos, arg);
        }
    }
    pthread_mutex_unlock(&click_record_queue_mutex);
}

