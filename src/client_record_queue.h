/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * client_record_queue.h
 * Original Author : chenjunpei@jarxi.com, 2016-7-7.
 *
 * Description
 */

#ifndef _CLIENT_RECORD_QUEUE_H_
#define _CLIENT_RECORD_QUEUE_H_

#include <time.h>
#include "list.h"

typedef struct client_record_queue_node_s {
    dlist_head_t    dlist;
    char            mac[MAC_ADDR_LEN];
    time_t          assoc_time;
} client_record_queue_node_t;

/**
 * init client_record_queue
 * @returns:
 *      0:      success
 *      other:  fail
 */
int client_record_queue_init();

/**
 * destory client_record_queue
 * @returns:
 *      void
 */
void client_record_queue_destory();

/**
 * enqueue a mac to client_record_queue
 * @mac:        the mac which to enqueue
 * @assoc_time  the time when the device associat to this WIFI
 * @returns:
 *      0:      success
 *      1:      existed, did not need to enqueue
 *      -1:     fail
 */
int client_record_queue_enqueue(char *mac, time_t assoc_time);

/**
 * dequeue a mac from client_record_queue
 * @buf:        the buf to receive the dequeued client
 * @retures:
 *      0:      success
 *      -1:     fail
 */
int client_record_queue_dequeue(client_record_queue_node_t *buf);

/**
 * delete a mac from client_record_queue
 * @mac:        the mac which going to delete
 * @assoc_time  the time when the device associat to this WIFI
 * @retures:
 *      0:      success
 *      -1:     fail
 */
int client_record_queue_delete(char *mac, time_t assoc_time);

/**
 * peek the lastest enqueue mac
 * @buf:        the buf to receive the lastest client
 * @returns:
 *      0:      success
 *      -1:     fail
 */
int client_record_queue_peek_last(client_record_queue_node_t *buf);

/**
 * print all mac in client_record_queue
 * @returns:
 *      void
 */
void client_record_queue_show_all();

typedef int (*CLIENT_RECORD_TRAVERSE_FUNC)(const client_record_queue_node_t *dev, _IN void *args);

/**
 * traverse ther client_record_queue
 * @returns:
 *      void
 */
void client_record_queue_traverse(_IN CLIENT_RECORD_TRAVERSE_FUNC func, _IN void *arg);

#endif      /* _CLIENT_RECORD_QUEUE_H_ */

