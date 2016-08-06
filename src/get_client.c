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
#include <linux/netlink.h>

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


#define GET_CLIENT_NETLINK      1
#define GET_CLIENT_PROC         0
#define GET_CLIENT_DEV          0


sem_t sem_client_access_get_mac;
static int fd;

#if GET_CLIENT_NETLINK
#define NETLINK_GET_CLIENT 30
#define MAX_PAYLOAD 1024
const static char *get_client_expect_msg = "get client ";

static int process_client(char *data)
{
    unsigned  char mac[MAC_ADDR_LEN]  = {0};
    int ret;

    if (!strstr(data, get_client_expect_msg)) {
        return -1;
    }
    sscanf(data + strlen(get_client_expect_msg), "%s", mac);

    debug(LOG_DEBUG, "get mac from client access device %s", mac);
    ret = siso_queue_set_mac(mac);
    if (ret == 1) {
        debug(LOG_DEBUG, "mac %s had existed in SISO queue", mac);
        return -1;
    } else if (ret == -1) {
        debug(LOG_INFO, "fail to enqueue mac %s to SISO queue", mac);
        return 0;
    }
    sem_post(&sem_client_access_get_mac);

    return 0;
}

int thread_get_client(char* arg)
{
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    static int sent_count = 0;

    (void)siso_queue_init();

    printf("netlink: %d\n", NETLINK_GET_CLIENT);

    fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_GET_CLIENT);
    if(fd<0) {
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    bind(fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (NULL == nlh) {
        return -1;
    }

    while (1) {
        memset(&dest_addr, 0, sizeof(dest_addr));
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;
        dest_addr.nl_groups = 0;

        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;

        strncpy(NLMSG_DATA(nlh), get_client_expect_msg, strlen(get_client_expect_msg) + 1);

        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        //printf("Sending message to kernel\n");
        if (!sent_count++) {
            sendmsg(fd,&msg,0);
        }
        recvmsg(fd, &msg, 0);
        //printf("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));
        process_client((char *)NLMSG_DATA(nlh));
    }

    careful_free(nlh);
    close(fd);
    siso_queue_destory();
    return 0;
}
#endif

#if (GET_CLIENT_PROC || GET_CLIENT_DEV)
int thread_get_client(char *arg)
{
    unsigned  char mac[MAC_ADDR_LEN];
    int ret;
    static int retry_time;

    (void)siso_queue_init();

OPEN_CLIENT_ACCESS:
#if GET_CLIENT_DEV
    fd = open("/dev/client_access", O_RDWR | O_NONBLOCK);
#endif
#if GET_CLIENT_PROC
    fd = open("/proc/client_access", O_RDWR | O_NONBLOCK);
#endif
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
#endif

void thread_get_client_exit(void)
{
    close(fd); /* this file can not close by system */
    siso_queue_destory();
}

