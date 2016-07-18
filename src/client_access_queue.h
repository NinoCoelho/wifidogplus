/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * client_access_queue.h
 * Original Author : cjpthree@126.com, 2015-7-11.
 *
 * Description
 */

#ifndef _CLIENT_ACCESS_QUEUE_H_
#define _CLIENT_ACCESS_QUEUE_H_

/**
 * init client_access_queue
 * @returns:
 *      0:      success
 *      other:  fail
 */
int client_access_queue_init();

/**
 * destory client_access_queue
 * @returns:
 *      void
 */
void client_access_queue_destory();

/**
 * enqueue a mac to client_access_queue
 * @mac:        the mac which to enqueue
 * @returns:
 *      0:      success
 *      1:      existed, did not need to enqueue
 *      -1:     fail
 */
int client_access_queue_enqueue(char *mac);

/**
 * dequeue a mac from client_access_queue
 * @buf:        the buf to receive the dequeued mac
 * @retures:
 *      0:      success
 *      -1:     fail
 */
int client_access_queue_dequeue(char *buf);

/**
 * delete a mac from client_access_queue
 * @mac:        the mac which going to delete
 * @retures:
 *      0:      success
 *      -1:     fail
 */
int client_access_queue_delete(char *mac);

/**
 * peek the lastest enqueue mac
 * @buf:        the buf to receive the lastest mac
 * @returns:
 *      0:      success
 *      -1:     fail
 */
int client_access_queue_peek_last(char *buf);

/**
 * print all mac in client_access_queue
 * @returns:
 *      void
 */
void client_access_queue_show_all();

#endif      /* _CLIENT_ACCESS_QUEUE_H_ */

