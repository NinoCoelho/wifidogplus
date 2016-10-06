/**
* Copyright(C) 2015. 1dcq. All rights reserved.
*
* siso_queue.c
* Original Author : cjpthree@126.com, 2015-6-29.
* v1: change to common siso queue by cjpthree@126.com 2016-9-10
*
* Description
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "siso_queue.h"

#ifndef debug
#define debug(level, format, ...) printf(format"\n", ## __VA_ARGS__)
#endif
#ifndef careful_free
#define careful_free(p) \
do { \
    if (p) { \
        free(p); \
        (p) = NULL; \
    } \
} while (0)
#endif
//#define strncasecmp memcmp

#define INIT_ELEMENT_DEF (1 << 7UL)
#define MAX_ELEMENT_DEF (INIT_ELEMENT_DEF * 4)


int siso_queue_init(siso_queue_t *queue, int node_size)
{
	memset(queue, 0, sizeof(siso_queue_t));
	queue->first_capacity = INIT_ELEMENT_DEF;
	queue->max_capacity = MAX_ELEMENT_DEF;
	queue->node_size = node_size;
	queue->capacity = queue->first_capacity;

	queue->elements = (char *)malloc(queue->capacity * node_size);
	if (!queue->elements) {
		return -1;
	}
	memset(queue->elements, 0, queue->capacity * node_size);

	return 0;
}

inline int siso_queue_size(siso_queue_t *queue)
{
	return ((queue->capacity - queue->front + queue->rear) % queue->capacity);
}

void siso_queue_set_max_capacity(siso_queue_t *queue, int max_capacity)
{
	queue->max_capacity = max_capacity;
}

inline int siso_queue_is_empty(siso_queue_t *queue)
{
	return (queue->front == queue->rear);
}

inline int siso_queue_is_full(siso_queue_t *queue)
{
	return (siso_queue_size(queue) == (queue->capacity - 1));
}

static inline int siso_queue_expand_space(siso_queue_t *queue)
{
	char *a = NULL;

	if (queue->capacity * 2 > queue->max_capacity) {
		debug(LOG_INFO, "can not expand any more");
		return -1;
	}

	a = (char *)realloc(queue->elements, queue->capacity * 2 * queue->node_size);
	if (!a) {
		debug(LOG_CRIT, "Failed to realloc");
		exit(1);
	}

	queue->elements = a;
	queue->capacity *= 2;

	return 0;
}

int siso_queue_enqueue(siso_queue_t *queue, void *node)
{
	if (siso_queue_is_full(queue)) {
		debug(LOG_ERR, "space not enough, expand space");
		if (siso_queue_expand_space(queue)) {
			return -1;
		}
	}

	memcpy(queue->elements + queue->rear * queue->node_size, node, queue->node_size);
	queue->rear = (queue->rear + 1) % queue->capacity;

	return 0;
}

int siso_queue_dequeue(siso_queue_t *queue, void *buf)
{
	if (siso_queue_is_empty(queue)) {
		debug(LOG_ERR, "queue is empty");
		return -1;
	}

	memcpy(buf, queue->elements + queue->front * queue->node_size, queue->node_size);
	memset(queue->elements + queue->front * queue->node_size, 0, queue->node_size);
	queue->front = (queue->front + 1) % queue->capacity;

	return 0;
}

void *siso_queue_peek_first(siso_queue_t *queue)
{
	if (siso_queue_is_empty(queue)) {
		debug(LOG_ERR, "queue is empty");
		return NULL;
	}

	return (void *)(queue->elements + queue->front * queue->node_size);
}

void *siso_queue_peek_last(siso_queue_t *queue)
{
	if (siso_queue_is_empty(queue)) {
		debug(LOG_ERR, "queue is empty");
		return NULL;
	}

	return (void *)(queue->elements + (queue->rear - 1) * queue->node_size);
}

int siso_queue_is_exsit(siso_queue_t *queue, void *node)
{
	int i;

	for (i = queue->front; i % queue->capacity < queue->rear; i++) {
		if (!strncasecmp(queue->elements + i * queue->node_size, node, queue->node_size)) {
			return 1;
		}
	}

	return 0;
}

void siso_queue_destory(siso_queue_t *queue)
{
	careful_free(queue->elements);
    memset(queue, 0, sizeof(siso_queue_t));
	return;
}

void siso_queue_print(siso_queue_t *queue)
{
	int i;

	if (!queue->elements) {
		debug(LOG_INFO, "siso_queue uninitialized");
		return;
	}

	printf("capacity %d\n", queue->capacity);
	printf("front %d\n", queue->front);
	printf("rear %d\n", queue->rear);
	printf("queue size %d\n", siso_queue_size(queue));
	for (i = queue->front; i % queue->capacity < queue->rear; i++) {
		//printf("enum %d is %s\n", i, queue->elements + i * queue->node_size);
	}
	printf("end\n");
}

void siso_queue_test_(void)
{
#ifndef MAC_ADDR_LEN
    #define MAC_ADDR_LEN 18
#endif
    typedef char mac_t[MAC_ADDR_LEN];
	char *mac = "00:00:00:00:22:24";
	char *mac1 = "10:00:00:00:22:25";
	char buf[MAC_ADDR_LEN];
	int i;
	siso_queue_t test_queue;
	siso_queue_t *queue = &test_queue;

	if (siso_queue_init(queue, MAC_ADDR_LEN)) {
		debug(LOG_ERR, "can not init QueueArray!");
		return;
	}
	debug(LOG_DEBUG, "queue size %d", siso_queue_size(queue));
	for (i = 0; i < INIT_ELEMENT_DEF; i++) {
		siso_queue_enqueue(queue, mac);
	}

	debug(LOG_DEBUG, "new comming enum is  %s", (char *)siso_queue_peek_last(queue));

	siso_queue_enqueue(queue, mac1);
	debug(LOG_DEBUG, "queue size %d", siso_queue_size(queue));
	for (i = 0; i < INIT_ELEMENT_DEF; i++) {
		siso_queue_dequeue(queue, buf);
	}

	debug(LOG_DEBUG, "dequeue enum is %s", buf);
	debug(LOG_DEBUG, "now top enum is  %s", (char *)siso_queue_peek_first(queue));
	siso_queue_dequeue(queue, buf);
	debug(LOG_DEBUG, "queue size %d", siso_queue_size(queue));
	siso_queue_dequeue(queue, buf);
	siso_queue_destory(queue);
}

void siso_queue_test(void)
{
#ifndef MAC_ADDR_LEN
    #define MAC_ADDR_LEN 18
#endif
	typedef struct node_s {
		int id;
		char mac[MAC_ADDR_LEN];
		int reserve;
	} node_t;
	node_t mac = {1, "00:00:00:00:22:24"};
	node_t mac1 = {2, "10:00:00:00:22:25"};
	node_t buf;
	int i;
	siso_queue_t test_queue;
	siso_queue_t *queue = &test_queue;

	if (siso_queue_init(queue, sizeof(node_t))) {
		debug(LOG_ERR, "can not init QueueArray!");
		return;
	}
	debug(LOG_DEBUG, "queue size %d", siso_queue_size(queue));
	for (i = 0; i < INIT_ELEMENT_DEF; i++) {
		siso_queue_enqueue(queue, &mac);
	}

	debug(LOG_DEBUG, "new comming enum is  %s", ((node_t *)siso_queue_peek_last(queue))->mac);

	siso_queue_enqueue(queue, &mac1);
	debug(LOG_DEBUG, "queue size %d", siso_queue_size(queue));
	for (i = 0; i < INIT_ELEMENT_DEF; i++) {
		siso_queue_dequeue(queue, &buf);
	}

	debug(LOG_DEBUG, "dequeue enum is %s", buf.mac);
	debug(LOG_DEBUG, "now top enum is  %s", ((node_t *)siso_queue_peek_first(queue))->mac);
	siso_queue_dequeue(queue, &buf);
	debug(LOG_DEBUG, "queue size %d", siso_queue_size(queue));
	siso_queue_dequeue(queue, &buf);
	siso_queue_destory(queue);
}

