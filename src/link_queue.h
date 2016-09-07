/**
 * Copyright(C) 2014. CJP All rights reserved.
 *
 * link_queue.h
 * Original Author : cjpthree@126.com, 2014-7-3.
 * v1: 2016-9-5 cjpthree@126.com add lock
 *
 * Description
 * link list
 */

#ifndef _LINK_QUEUE_H_
#define _LINK_QUEUE_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "slist.h"

void test_link_queue();

#define LINK_QUEUE_MAX_LEN_DEF (1 << 16UL)

#ifndef careful_free
#define careful_free(p) \
do { \
    if (p) { \
        free(p); \
        (p) = NULL; \
    } \
} while (0)
#endif

/* define the lock */
#define LOCK_TYPE 1
#if (LOCK_TYPE == 1) /* for unix */
#include <pthread.h>
typedef pthread_mutex_t         mutex_type;
#define mutex_lock(mutex)       pthread_mutex_lock(&mutex)
#define mutex_unlock(mutex)     pthread_mutex_unlock(&mutex)
#define great_mutex()           PTHREAD_MUTEX_INITIALIZER
#define delete_mutex(mutex)     pthread_mutex_destory(&mutex)
#endif
#if (LOCK_TYPE == 2) /* for all */
typedef unsigned char           mutex_type;
#define mutex_lock(mutex)       {while(mutex); (mutex)++;}
#define mutex_unlock(mutex)     (mutex)--
#define great_mutex()           0
#define delete_mutex(mutex)
#endif
#if (LOCK_TYPE == 3) /* for windows */
#include <Windows.h>
typedef HANDLE                  mutex_type;
#define mutex_lock(mutex)       WaitForSingleObject((mutex), INFINITE)
#define mutex_unlock(mutex)     ReleaseMutex(mutex)
#define great_mutex()           CreateMutex(NULL, FALSE, NULL)
#define delete_mutex(mutex)     CloseHandle(mutex)
#endif

/* the queue's node */
typedef struct link_queue_node_s {
    slist_node_t node;
    void *data;         /* the user's data */
} link_queue_node_t;

/* the queue's head */
typedef struct link_queue_s {
    slist_head_t node;
    mutex_type   queue_mutex;   /* the mutex lock */
    unsigned int cur_len;       /* record the queue's length */
    unsigned int max_len;       /* queue's max length */
} link_queue_t;

/**
 * function: init a queue
 * @queue_name: the queue's name
 * returns:
 *     the pointer of the queue
 */
#define link_queue_init(queue_name) \
{ \
    SLIST_HEAD_INIT((queue_name).node), \
    great_mutex(), \
    0, \
    LINK_QUEUE_MAX_LEN_DEF \
}

/**
 * function: set the queue's length
 * @queue: the pointer of the queue
 * @len: the max length of the queue
 * returns:
 *     none
 */
#define link_queue_set_max_len(queue, len) \
do { \
    mutex_lock((queue)->queue_mutex); \
    (queue)->max_len = (len); \
    mutex_unlock((queue)->queue_mutex); \
} while (0)

/**
 * function: alloc memory for a node
 * @node: the pointer to store the creating node
 * @data_size: the size of the data in the node
 * returns:
 *     none
 */
#define link_queue_alloc_node(node, data_size) \
do { \
    node = (link_queue_node_t *)malloc(sizeof(link_queue_node_t)); \
    if (!node) { \
        break; \
    } \
    memset(node, 0, sizeof(link_queue_node_t)); \
    if (data_size) { \
        void *data = malloc(data_size); \
        if (!data) { \
            careful_free(node); \
            break; \
        } \
        memset(data, 0, sizeof(data_size)); \
        node->data = data; \
    } \
} while (0)

/**
 * function: init a node
 * @node: the pointer to the node
 * @srcdata: the source data, will copy to the data in the node
 * @data_size: the size of the data in the node
 * returns:
 *     none
 */
#define link_queue_init_node(node, srcdata, data_size) \
do { \
    INIT_SLIST_NODE((slist_node_t *)(node)); \
    memcpy(node->data, srcdata, data_size); \
} while (0)

/**
 * function: create a node
 * @node: the pointer to the node
 * @srcdata: the source data, will copy to the data in the node
 * @data_size: the size of the data in the node
 * returns:
 *     none
 */
#define link_queue_create_node(node, srcdata, data_size) \
do { \
    node = NULL; \
    link_queue_alloc_node(node, data_size); \
    if (!node) { \
        break; \
    } \
    link_queue_init_node(node, srcdata, data_size); \
} while (0)

/**
 * function: free the memory of a node
 * @node: the pointer of the node
 * returns:
 *     none
 */
#define link_queue_free_node(node) \
do { \
    if (node) { \
        careful_free(node->data); \
        careful_free(node); \
    } \
} while (0)

/**
 * function: check if the queue is empty
 * @queue: the pointer of the queue
 * returns:
 *     1: empty
 *     0: no empty
 */
#define link_queue_is_empty(queue) \
    ((queue)->cur_len == 0)

/**
 * function: enqueue
 * @queue: the pointer of the queue
 * @en_node: node to enqueue
 * returns:
 *     none
 */
#define link_queue_enqueue(queue, en_node) \
do { \
    mutex_lock((queue)->queue_mutex); \
    if ((queue)->cur_len >= (queue)->max_len) { \
        link_queue_node_t *de_node = (link_queue_node_t *)slist_get_first((slist_head_t *)(queue)); \
        slist_del_head((slist_head_t *)(queue)); \
        if (de_node) { \
            careful_free(de_node->data); \
            careful_free(de_node); \
        } \
        slist_add_tail((slist_node_t *)(en_node), (slist_head_t *)(queue)); \
    } else { \
        slist_add_tail((slist_node_t *)(en_node), (slist_head_t *)(queue)); \
        (queue)->cur_len++; \
    } \
    mutex_unlock((queue)->queue_mutex); \
} while (0)

/**
 * function: dequeue
 * @queue: the pointer of the queue
 * @de_node: buf to store dequeue node
 * returns:
 *     none
 */
#define link_queue_dequeue(queue, de_node) \
do { \
    mutex_lock((queue)->queue_mutex); \
    if (!slist_empty((slist_head_t *)(queue))) { \
        de_node = (link_queue_node_t *)slist_get_first((slist_head_t *)(queue)); \
        slist_del_head((slist_head_t *)(queue)); \
        (queue)->cur_len--; \
    } else { \
        (queue)->cur_len = 0; \
    } \
    mutex_unlock((queue)->queue_mutex); \
} while (0)

/**
 * function: parse the data of the node
 * @node: the pointer of the node
 * @data_type: the real type of the data in the node
 * returns:
 *     the pointer of the data
 */
#define link_queue_parse_data(node, data_type) \
    ((data_type *)(node->data))

/**
 * function: peek the first node
 * @queue: the pointer of the queue
 * returns:
 *     the pointer of first entry
 */
#define link_queue_peek_first(queue) \
    (link_queue_node_t *)slist_get_first((slist_head_t *)(queue))

/**
 * function: peek the last node
 * @queue: the pointer of the queue
 * returns:
 *     the pointer of last node
 */
#define link_queue_peek_last(queue) \
    (link_queue_node_t *)slist_get_last((slist_head_t *)(queue))

/**
 * function: the callback function for link_queue_traverse
 * @node: the pointer of the node
 * @args: the parameters of func which come from link_queue_traverse
 * attention:
 *      can not call this file's function in this function, or may be make deadlock
 * returns:
 *      0: success
 *      other: fail
 */
typedef int (*LINK_QUEUE_TRAVERSE_FUNC)(const link_queue_node_t *node, void *args);

/**
 * function: traverse the queue
 * @queue: the pointer of the queue
 * @func: the LINK_QUEUE_TRAVERSE_FUNC type function
 * @args: the parameters of func which input
 * returns:
 *      none
 */
#define link_queue_traverse(queue, func, args) \
do { \
    slist_node_t      *pos_prev; \
    slist_node_t      *pos; \
    mutex_lock((queue)->queue_mutex); \
    slist_for_each_safe(pos_prev, pos, (slist_head_t *)(queue)) { \
        if (NULL != func) { \
            (void)func((link_queue_node_t *)pos, args); \
        }\
    } \
    mutex_unlock((queue)->queue_mutex); \
} while (0)

#endif      /* _LINK_QUEUE_H_ */

