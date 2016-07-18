/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * getaddress_thread.h
 * Original Author : cjpthree@126.com, 2015-5-7.
 *
 * Description
 */



#ifndef _GETADDRESS_THREAD_H_
#define _GETADDRESS_THREAD_H_

extern pthread_cond_t          get_address_thread_cond;
extern pthread_mutex_t         get_address_thread_cond_mutex;

void thread_getaddress(char *arg);

#endif      /* _GETADDRESS_THREAD_H_ */

