/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * wifiga_ubus_client.h
 * Original Author : chenjunpei@jarxi.com, 2016-9-5.
 *
 * Description
 */

#ifndef _UBUS_CLIENT_H_
#define _UBUS_CLIENT_H_

#include <libubox/ustream.h>

#include "libubus.h"

int onoffline_enqueue(char *mac, int isonline, char *rssi, time_t time);

int wifiga_ubus_client_main_loop(void *ubus_socket);

void wifiga_ubus_client_exit(void);


int ubus_send(const char *type, struct blob_attr *data);

int ubus_call(const char *path, const char *method, struct blob_attr *data, void *ret);

int ubus_init(void);

void ubus_destory();

int report_onoffline(const char *mac, int onoffline_type);

void test_auto_conn(void);


#endif      /* _UBUS_CLIENT_H_ */

