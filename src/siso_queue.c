/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * siso_queue.c
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

#define CAP (1 << 7UL)
#define MAX_ELEMENT (CAP * 4)

typedef char mac_t[MAC_ADDR_LEN];

/* a position is always empty */
static char *elements = NULL;
static int capacity = CAP; /* avoid 0 */
static int front = 0;
static int rear = 0;

int siso_queue_init(void)
{
    if (elements) {
        debug(LOG_INFO, "siso_queue initialized");
        return 0;
    }

    elements = (char *)safe_malloc(CAP * MAC_ADDR_LEN);

    memset(elements, 0, CAP * MAC_ADDR_LEN);
    capacity = CAP;
    front = 0;
    rear = 0;

    return 0;
}

static inline int siso_queue_size(void)
{
    return ((capacity - front + rear) % capacity);
}

static inline int siso_queue_is_empty(void)
{
    return (front == rear);
}

static inline int siso_queue_is_full(void)
{
    return (siso_queue_size() == (capacity - 1));
}

static inline int siso_queue_expand_space(void)
{
    char *a = NULL;

    if (capacity * 2 > MAX_ELEMENT) {
        debug(LOG_INFO, "can not expand any more");
        return -1;
    }

    a = (char *)realloc(elements, capacity * 2 * MAC_ADDR_LEN);
    if (!a) {
        debug(LOG_CRIT, "Failed to realloc");
        exit(1);
    }

    elements = a;
    capacity *= 2;

    return 0;
}

static inline int siso_queue_enqueue(char *mac)
{
    if (siso_queue_is_full()) {
        debug(LOG_ERR, "space not enough, expand space");
        if (siso_queue_expand_space()) {
            return -1;
        }
    }

    memcpy(elements + rear * MAC_ADDR_LEN, mac, MAC_ADDR_LEN);
    rear = (rear + 1) % capacity;

    return 0;
}

static inline int siso_queue_dequeue(char *buf)
{
    if (siso_queue_is_empty()) {
        debug(LOG_ERR, "queue is empty");
        return -1;
    }

    memcpy(buf, elements + front * MAC_ADDR_LEN, MAC_ADDR_LEN);
    memset(elements + front * MAC_ADDR_LEN, 0, MAC_ADDR_LEN);
    front = (front + 1) % capacity;

    return 0;
}

static inline char *siso_queue_peek(void)
{
    if (siso_queue_is_empty()) {
        debug(LOG_ERR, "queue is empty");
        return NULL;
    }

    return (elements + front * MAC_ADDR_LEN);
}

static inline char *siso_queue_peek_new(void)
{
    if (siso_queue_is_empty()) {
        debug(LOG_ERR, "queue is empty");
        return NULL;
    }

    return (elements + (rear - 1) * MAC_ADDR_LEN);
}

static inline int siso_queue_is_exsit(char *mac)
{
    int i;

    for (i = front; i % capacity < rear; i++) {
        if (!strncasecmp(elements + i * MAC_ADDR_LEN, mac, MAC_ADDR_LEN)) {
            return 1;
        }
    }

    return 0;
}

inline void siso_queue_destory(void)
{
    careful_free(elements);
    return;
}

void siso_queue_print(void)
{
    int i;

    if (!elements) {
        debug(LOG_INFO, "siso_queue uninitialized");
        return;
    }

    printf("capacity %d\n", capacity);
	printf("front %d\n", front);
	printf("rear %d\n", rear);
	printf("queue size %d\n", siso_queue_size());
    for (i = front; i % capacity < rear; i++) {
        printf("enum %d is %s\n", i, elements + i * MAC_ADDR_LEN);
    }
    printf("end\n");
}

int siso_queue_get_mac(char *buf)
{
    if (!buf) {
        return -1;
    }

    return siso_queue_dequeue(buf);
}

int siso_queue_set_mac(char *mac)
{
    if (!mac) {
        return -1;
    }

    if (siso_queue_is_exsit(mac)) {
        return 1;
    }

    return siso_queue_enqueue(mac);
}

void siso_queue_test(void)
{
    char *mac = "00:00:00:00:22:24";
    char *mac1 = "00:00:00:00:22:25";
    char buf[MAC_ADDR_LEN];
    int i;

    if (siso_queue_init()) {
        debug(LOG_ERR, "can not init QueueArray!");
        return;
    }
    debug(LOG_DEBUG, "queue size %d", siso_queue_size());
    for (i = 0; i < CAP; i++) {
        siso_queue_enqueue(mac);
    }

    debug(LOG_DEBUG, "new comming enum is  %s", siso_queue_peek_new());

    siso_queue_enqueue(mac1);
    debug(LOG_DEBUG, "queue size %d", siso_queue_size());
    for (i = 0; i < CAP; i++) {
        siso_queue_dequeue(buf);
    }

    debug(LOG_DEBUG, "dequeue enum is %s", buf);
    debug(LOG_DEBUG, "now top enum is  %s", siso_queue_peek());
    siso_queue_dequeue(buf);
    debug(LOG_DEBUG, "queue size %d", siso_queue_size());
    siso_queue_dequeue(buf);
    siso_queue_destory();
}

