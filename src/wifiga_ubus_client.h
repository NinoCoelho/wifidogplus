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

int onoffline_enqueue(char *mac, int isonline, char *rssi, time_t time);

int wifiga_ubus_client_main_loop(const char *ubus_socket);

void wifiga_ubus_client_exit(void);

#endif      /* _UBUS_CLIENT_H_ */

