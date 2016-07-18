/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * siso_queue.h
 * Original Author : cjpthree@126.com, 2015-6-29.
 *
 * Description
 *         a single in single out queue which can free lock.
 */

#ifndef _SISO_QUEUE_H_
#define _SISO_QUEUE_H_

/**
 * init siso_queue
 * @returns:
 *      0:      success
 *      other:  fail
 */
int siso_queue_init();

/**
 * destory client_access_queue
 * @returns:
 *      void
 */
void siso_queue_destory();

/**
 * dump siso_queue
 * @returns:
 *      void
 */
void siso_queue_print();

/**
 * dequeue a mac from siso_queue
 * @buf:        the buf to receive the dequeued mac
 * @retures:
 *      0:      success
 *      -1:     fail
 */
int siso_queue_get_mac(char *buf);

/**
 * enqueue a mac to siso_queue
 * @mac:        the mac which to enqueue
 * @returns:
 *      0:      success
 *      1:      existed, did not need to enqueue
 *      -1:     fail
 */
int siso_queue_set_mac(char *mac);

/**
 * siso_queue test function
 * @returns:
 *      void
 */
void siso_queue_test();

#endif      /* _SISO_QUEUE_H_ */

