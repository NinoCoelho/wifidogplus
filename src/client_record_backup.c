/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * client_record_backup.c
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
#include <semaphore.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "client_record_backup.h"
#include "client_record_queue.h"


#define CLIENT_RECORD_FILE "/tmp/wifidog_client_record"


static int client_record_restore_dev(char *mac, int assoc_time)
{
    int ret = 0;

    if (!is_mac_valid(mac)) {
        return -1;
    }

    debug(LOG_DEBUG, "restore mac %s assoc_time %d", mac, assoc_time);
    ret = client_record_queue_enqueue(mac, assoc_time);
    if (ret == 1) {
        debug(LOG_DEBUG, "mac %s had existed in client record queue", mac);
        return 0;
    } else if (ret == -1) {
        debug(LOG_DEBUG, "fail to enqueue mac %s to client record queue", mac);
        return -1;
    }

    return 0;
}

int client_record_restore_from_file(void)
{
    FILE *file;
    char mac[MAC_ADDR_LEN] = {0};
    char assoc_time[32] = {0};
    int ret;

    if (!(file = fopen(CLIENT_RECORD_FILE, "r"))) {
        debug(LOG_INFO, "can not open %s, it may be not exist", CLIENT_RECORD_FILE);
        return -1;
    }

    while (!feof(file)) {
        memset(mac, 0, MAC_ADDR_LEN);
        memset(assoc_time, 0, sizeof(assoc_time) / sizeof(assoc_time[0]));
        ret = fscanf(file, "%s %s\n", mac, assoc_time);
        if (ret != 2) {
            break;
        }
        (void)client_record_restore_dev(mac, atoi(assoc_time));
    }

    fclose(file);
    return 0;
}

static int client_record_store_dev(client_record_queue_node_t *dev, FILE *file)
{
    int ret;

    ret = fprintf(file, "%s %d\n", dev->mac, dev->assoc_time);
    if (ret == -1) {
        debug(LOG_ERR, "fail to backup dev %s", dev->mac);
        return -1;
    }

    return 0;
}

int client_record_refresh(void)
{
    FILE *file;

    if (!(file = fopen(CLIENT_RECORD_FILE, "w+"))) {
        debug(LOG_ERR, "fail to open %s", CLIENT_RECORD_FILE);
        return -1;
    }

    //client_record_queue_show_all();
    client_record_queue_traverse((CLIENT_RECORD_TRAVERSE_FUNC)client_record_store_dev, file);

    fclose(file);
    return 0;
}

