/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file common.h
    @brief Common constants and other bits
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _COMMON_H_
#define _COMMON_H_

#ifndef _IN
#define _IN
#endif
#ifndef _OUT
#define _OUT
#endif

#define __OPENWRT__
//#define __MTK_SDK__

#ifdef __MTK_SDK__
#include "libblink.h"
#include "nvram.h"
#endif


#define IPTABELES_VESION    (1410)

#define MINIMUM_STARTED_TIME 1041379200 /* 2003-01-01 */

#define RET_SUCCESS         0

#define fdebug(level, format, ...) fprintf(stdout, "%s:%s:%d: "format"\n", __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define _CHECK_CAREFUL_                     1

#define WIFIDOG_ON_OFF                      1 /* slecting 0 close most of wifidog feature */
#define OPEN_THREAD_TEST                    (0)
#if 1
#define OPEN_THREAD_WATCHDOG                1
#define OPEN_THREAD_CLIENT_ACCESS           1
#define OPEN_THREAD_CLIENT_TIMEOUT_CHECK    1
#define OPEN_THREAD_WDCTL                   1
#define OPEN_THREAD_PING                    1
#define OPEN_THREAD_WIFIGA_UBUS_CLIENT      1
#define OPEN_THREAD_WHITE_LIST              0
#define OPEN_THREAD_EXG_PROTOCOL            0
#define OPEN_THREAD_GETADDRESS              (0)

#define OPEN_INIT_FW                        1
#define OPEN_CHECK_NETWORK                  0
#endif

#define SUCCESS_TO_RECENT_URL               0

/* allow first, have a better experience; deny first, save more traffic */
#define ALLOW_FIRST                         0

//define OFFLINE_CLEAR_FW

/* Anti DoS support */
#define ANTI_DOS        0
/* Anti DoS timeout, Units are seconds */
#define ANTI_DOS_TIME   (8UL)
/* in Anti DoS timeout, max access limit */
#define ANTI_DOS_LIMIT  (12UL)

#define RETRY_MAX_TIME  (2UL)
#define REFRESH_TIME    (10 * 60UL)

/** @brief Read buffer for socket read? */
#define MAX_BUF         (4096UL)
#define POPEN_MAX_BUF   (4096 * 4UL)
#define MAC_ADDR_LEN    (18UL)
#define MAX_IPV4_LEN    (17UL)
#define MAX_TOKEN_LEN   (128UL)
#define MAX_ACCOUNT_LEN (256UL)
#define MAX_OPENID_LEN  (128UL)
#define MAX_HOST_NAME_LEN   (128UL)
#define MAX_INTERFACE_NAME_LEN (16UL)
#define MAX_RECORD_URL_LEN (512UL)
#define HTTP_TIMEOUT    (40UL)
#define PHONE_NUMBER_LEN (11 + 1UL)

#define DUMY_IP         "0.0.0.0"
#define DUMY_TOKEN      "0"
#define DUMY_ACCOUNT    "0"
#define DUMY_OPENID     "0"
#define DUMY_HOST_NAME  "unkown"
#define DUMY_REQ_URL    "http://www.baidu.com"

#define CLIENT_RSSI_DEF (-75)

enum {
	OK,
	ERR_noServer =1,
	ERR_TIMEOUT,
	ERR_READ
};

typedef enum {
    AUTH_LOCAL_ONEKEY_AUTO = 0,
    AUTH_LOCAL_ONEKEY_MANUAL,
    AUTH_LOCAL_WECHAT,
    AUTH_LOCAL_APPCTL,
    AUTH_SERVER_XIECHENG = 11,
} Auth_mode_e;

#define IS_LOCAL_AUTH(mode) ((mode) < AUTH_SERVER_XIECHENG && (mode) > AUTH_LOCAL_ONEKEY_AUTO)

typedef struct system_info_s {
    char *version;
    char *model;
    char *creation_date;
    char *snid;
    int info_ok;
} system_info_t;

#endif /* _COMMON_H_ */

