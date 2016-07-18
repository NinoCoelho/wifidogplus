/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * watchdog.h
 * Original Author : cjpthree@126.com, 2015-7-31.
 *
 * Description
 */

#ifndef _WATCHDOG_H_
#define _WATCHDOG_H_

#include <stdio.h>

#define DEF_THREAD_WATCHDOG_TIMEOUT     (15UL)   /* config_get_config()->checkinterval times */
#define MAX_DO_COMMAND_CONTINUE         (6UL)    /* do command for this define times continuously, then must feed watchdog */

#define THREAD_PING_NAME            "thread_ping"
#define THREAD_EXG_PROTOCOL_NAME    "exg_protocol"
#define THREAD_WHITE_LIST_NAME      "white_list"
#define THREAD_GETADDRESS_NAME      "getaddress"
#define THREAD_GET_CLIENT_NAME      "get_client"
#define THREAD_FW_COUNTER_NAME      "fw_counter"
#define THREAD_TEST_NAME            "test_thread"


#define pthread_watchdog_feed(name)       _watchdog_feed_(name)


/**
 *check network
 * returns:
 *  1: work well
 *  0: work error
 */
int is_network_welldone();

/* restart network */
void network_restart();

void thread_watchdog(char*);

void pthread_watchdog_dump_list();

int pthread_watchdog_is_exist(char *name);

int pthread_watchdog_register(char *name);

void restart_system();

int _watchdog_feed_(char *name);


#define OVERFLOW_FEED(thread, count, max) \
do { \
    (count)++; \
    if ((count) > (max)) { \
        pthread_watchdog_feed(thread); \
        (count) = 0; \
    } \
} while (0)

#endif      /* _WATCHDOG_H_ */

