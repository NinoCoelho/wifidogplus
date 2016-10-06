/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * siso_queue.h
 * Original Author : cjpthree@126.com, 2015-6-29.
 * v1: change to common siso queue by cjpthree@126.com 2016-9-10
 *
 * Description
 *      a single in single out queue which can free lock.
 *      siso_queue is very fast.
 *      but can not using in more than two thread, and memory increase all the time.
 *      every node must have same size.
 */

#ifndef _SISO_QUEUE_H_
#define _SISO_QUEUE_H_


typedef struct siso_queue_s {
	char *elements;     /* point to elements */
	int capacity;       /* capacity, must avoid 0 */
	int front;          /* front of queue */
	int rear;           /* rear of queue */
	int node_size;      /* node size */
	int first_capacity; /* capacity of init */
	int max_capacity;   /* max capacity */
} siso_queue_t;


/**
 * init siso_queue
 * @queue: the queue
 * @node_size: node size
 * @returns:
 *      0:      success
 *      other:  fail
 */
int siso_queue_init(siso_queue_t *queue, int node_size);

/**
 * get siso_queue current size
 * @queue: the queue
 * @returns:
 *      the size
 */
inline int siso_queue_size(siso_queue_t *queue);

/**
 * check siso_queue is empty or not
 * @queue: the queue
 * @returns:
 *      1: empty
 *      0: no empty
 */
inline int siso_queue_is_empty(siso_queue_t *queue);

/**
 * check siso_queue is full or not
 * @queue: the queue
 * @returns:
 *      1: full
 *      0: no full
 */
inline int siso_queue_is_full(siso_queue_t *queue);

/**
 * set max_capacity for siso_queue
 * @queue: the queue
 * @max_capacity: max_capacity
 * @returns:
 *      none
 */
void siso_queue_set_max_capacity(siso_queue_t *queue, int max_capacity);

/**
 * enqueue
 * @queue: the queue
 * @node: the node to enqueue
 * @returns:
 *      0:      success
 *      other:  fail
 */
int siso_queue_enqueue(siso_queue_t *queue, void *node);

/**
 * dequeue
 * @queue: the queue
 * @node: the buf to store the dequeue node
 * @returns:
 *      0:      success
 *      other:  fail
 */
int siso_queue_dequeue(siso_queue_t *queue, void *buf);

/**
 * peek first enqueue node
 * @queue: the queue
 * @returns:
 *      the first enqueue node
 */
void *siso_queue_peek_first(siso_queue_t *queue);

/**
 * peek last enqueue node
 * @queue: the queue
 * @returns:
 *      the last enqueue node
 */
void *siso_queue_peek_last(siso_queue_t *queue);

/**
 * check if a node in queue yet
 * @queue: the queue
 * @node: the node
 * @returns:
 *      1: in queue yet
 *      0: not in queue
 */
int siso_queue_is_exsit(siso_queue_t *queue, void *node);

/**
 * destory client_access_queue
 * @queue: the queue
 * @returns:
 *      void
 */
void siso_queue_destory(siso_queue_t *queue);

/**
 * dump siso_queue
 * @queue: the queue
 * @returns:
 *      void
 */
void siso_queue_print(siso_queue_t *queue);

/**
 * siso_queue test function
 * @returns:
 *      void
 */
void siso_queue_test_(void);

/**
 * siso_queue test function
 * @returns:
 *      void
 */
void siso_queue_test();

#endif      /* _SISO_QUEUE_H_ */

