/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * get_client.c
 * Original Author : cjpthree@126.com, 2015-6-29.
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


sem_t sem_client_access_get_mac;
static int fd;


int thread_get_client(char *arg)
{
    unsigned  char mac[MAC_ADDR_LEN];
    int ret;
    static int retry_time;

    (void)siso_queue_init();

OPEN_CLIENT_ACCESS:
    //fd = open("/dev/client_access", O_RDWR | O_NONBLOCK);
    fd = open("/proc/client_access", O_RDWR | O_NONBLOCK);
    if (fd < 0)    {
        debug(LOG_ERR, "fail to open client access device!");
        (void)execute_cmd("insmod client_access", NULL);
        sleep(5);
        if (retry_time++ < RETRY_MAX_TIME) {
            goto OPEN_CLIENT_ACCESS;
        } else {
            siso_queue_destory();
            return 0; /* normal termination */
        }
    }

    while(1)
    {
        memset(mac, 0, MAC_ADDR_LEN);
        if (read(fd, mac, MAC_ADDR_LEN) != MAC_ADDR_LEN) {
            debug(LOG_DEBUG, "fail to get a mac!");
            continue;
        }

        debug(LOG_DEBUG, "get mac from client access device %s", mac);
        ret = siso_queue_set_mac(mac);
        if (ret == 1) {
            debug(LOG_DEBUG, "mac %s had existed in SISO queue", mac);
            continue;
        } else if (ret == -1) {
            debug(LOG_INFO, "fail to enqueue mac %s to SISO queue", mac);
            continue;
        }
        sem_post(&sem_client_access_get_mac);
    }

    close(fd);
    siso_queue_destory();

    return 0;
}

void thread_get_client_exit(void)
{
    close(fd); /* this file can not close by system */
    siso_queue_destory();
}

