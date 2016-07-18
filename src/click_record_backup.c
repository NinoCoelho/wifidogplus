/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * click_record_backup.c
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
#include <semaphore.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "click_record_backup.h"
#include "click_record_queue.h"


#define CLICK_RECORD_FILE "/tmp/wifidog_click_record"


static int click_record_restore_item(char *appid, char *mac, int type, int time)
{
    int ret = 0;

    if (!appid || !is_mac_valid(mac)) {
        return -1;
    }

    debug(LOG_DEBUG, "restore appid %s mac %s type %d time %d", appid, mac, type, time);
    ret = click_record_queue_enqueue(appid, mac, type, time);
    if (ret == 1) {
        debug(LOG_DEBUG, "item %s had existed in click record queue", mac);
        return 0;
    } else if (ret == -1) {
        debug(LOG_DEBUG, "fail to add item %s to click record queue", mac);
        return -1;
    }

    return 0;
}

int click_record_restore_from_file(void)
{
    FILE *file;
    char appid[APPID_LEN] = {0};
    char mac[MAC_ADDR_LEN] = {0};
    char type[32] = {0};
    char time[32] = {0};
    int ret;

    if (!(file = fopen(CLICK_RECORD_FILE, "r"))) {
        debug(LOG_INFO, "can not open %s, it may be not exist", CLICK_RECORD_FILE);
        return -1;
    }

    while (!feof(file)) {
        memset(appid, 0, APPID_LEN);
        memset(mac, 0, MAC_ADDR_LEN);
        memset(type, 0, sizeof(type) / sizeof(type[0]));
        memset(time, 0, sizeof(time) / sizeof(time[0]));
        ret = fscanf(file, "%s %s %s %s\n", appid, mac, type, time);
        if (ret != 4) {
            break;
        }
        (void)click_record_restore_item(appid, mac, atoi(type), atoi(time));
    }

    fclose(file);
    return 0;
}

static int click_record_store_item(click_record_queue_node_t *item, FILE *file)
{
    int ret;

    ret = fprintf(file, "%s %s %d %d\n", item->appid, item->mac, item->type, item->click_time);
    if (ret == -1) {
        debug(LOG_ERR, "fail to backup item");
        return -1;
    }

    return 0;
}

int click_record_refresh(void)
{
    FILE *file;

    if (!(file = fopen(CLICK_RECORD_FILE, "w+"))) {
        debug(LOG_ERR, "fail to open %s", CLICK_RECORD_FILE);
        return -1;
    }

    //click_record_queue_show_all();
    click_record_queue_traverse((CLICK_RECORD_TRAVERSE_FUNC)click_record_store_item, file);

    fclose(file);
    return 0;
}

