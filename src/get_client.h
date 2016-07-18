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

extern sem_t sem_client_access_get_mac;

int thread_get_client(char *arg);

/* get a mac from circular array
 * attention: must be "single in single out", if not you should using mutex lock
 */
int get_client_get_mac(char *buf);

/* set a mac to circular array
 * attention: must be "single in single out", if not you should using mutex lock
 */
int get_client_set_mac(char *mac);

/* peek a mac from circular array, did not delete the getting mac
 * attention: must be "single in single out", if not you should using mutex lock
 */
int get_client_peek_mac(char *buf);

void get_client_show_all();


#endif      /* _GET_CLIENT_H_ */

