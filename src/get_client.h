/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * get_client.h
 * Original Author : cjpthree@126.com, 2015-6-29.
 *
 * Description
 */

#ifndef _GET_CLIENT_H_
#define _GET_CLIENT_H_

#include <semaphore.h>
#include "siso_queue.h"

typedef struct client_node_s {
	char mac[MAC_ADDR_LEN];
	int rssi;
} client_node_t;

extern sem_t sem_client_access_get_mac;

int thread_get_client(char *arg);

/**
 * dequeue a client from siso_queue
 * @buf:        the buf to receive the dequeued client
 * @retures:
 *      0:      success
 *      -1:     fail
 */
int get_client_dequeue(client_node_t *buf);

/**
 * enqueue a client to siso_queue
 * @mac:        the mac which to enqueue
 * @rssi:       rssi
 * @returns:
 *      0:      success
 *      1:      existed, did not need to enqueue
 *      -1:     fail
 */
int get_client_enqueue(char *mac, int rssi);

#endif      /* _GET_CLIENT_H_ */

