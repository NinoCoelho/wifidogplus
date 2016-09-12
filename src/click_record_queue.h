/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * click_record_queue.h
 * Original Author : chenjunpei@jarxi.com, 2016-7-11.
 *
 * Description
 */

#ifndef _CLICK_RECORD_QUEUE_H_
#define _CLICK_RECORD_QUEUE_H_

#include <time.h>
#include "list.h"

#define APPID_LEN           (32UL)

typedef struct click_record_queue_node_s {
    dlist_head_t    dlist;
    char            appid[APPID_LEN];
    char            mac[MAC_ADDR_LEN];
    int             type;
    time_t          click_time;
} click_record_queue_node_t;

/**
 * init click_record_queue
 * @returns:
 *      0:      success
 *      other:  fail
 */
int click_record_queue_init();

/**
 * destory click_record_queue
 * @returns:
 *      void
 */
void click_record_queue_destory();

/**
 * enqueue a mac to click_record_queue
 * @appid:      appid
 * @mac:        the mac which to enqueue
 * @type:       app type
 * @click_time  the time when the click happened
 * @returns:
 *      0:      success
 *      1:      existed, did not need to enqueue
 *      -1:     fail
 */
int click_record_queue_enqueue(char *appid, char *mac, int type, time_t click_time);


/**
 * dequeue a mac from click_record_queue
 * @buf:        the buf to receive the dequeued click
 * @retures:
 *      0:      success
 *      -1:     fail
 */
int click_record_queue_dequeue(click_record_queue_node_t *buf);

/**
 * peek the lastest enqueue mac
 * @buf:        the buf to receive the lastest click
 * @returns:
 *      0:      success
 *      -1:     fail
 */
int click_record_queue_peek_last(click_record_queue_node_t *buf);

/**
 * print all mac in click_record_queue
 * @returns:
 *      void
 */
void click_record_queue_show_all();

typedef int (*CLICK_RECORD_TRAVERSE_FUNC)(const click_record_queue_node_t *click, _IN void *args);

/**
 * traverse ther click_record_queue
 * @returns:
 *      void
 */
void click_record_queue_traverse(_IN CLICK_RECORD_TRAVERSE_FUNC func, _IN void *arg);

#endif      /* _CLICK_RECORD_QUEUE_H_ */

