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
/** @file util.h
    @brief Misc utility functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#include "common.h"

#define STATUS_BUF_SIZ	65536

extern unsigned long tracked_clients_num;

int do_execute(char *fmt, ...);

/** @brief Execute a shell command
 */
//int execute(const char *cmd_line, int quiet);

int execute_not_care(const char *cmd_line, int quiet);

int COMM_RunCommandWithTimeout(int timeout/* SECOND */, const char *command);

/** @brief Execute a shell command, return a result string
 */
int execute_cmd(const char *cmd, char *result_buf);

struct in_addr *wd_gethostbyname(const char *name);

/* @brief Get IP address of an interface */
char *get_iface_ip(const char *ifname);

/* @brief Get MAC address of an interface */
char *get_iface_mac(const char *ifname);
char *get_gw_mac(const char *ifname);

/* @brief Get interface name of default gateway */
char *get_ext_iface (void);

int getIfMac(char *ifname, char *if_hw);

/* @brief Sets hint that an online action (dns/connect/etc using WAN) succeeded */
void mark_online();
/* @brief Sets hint that an online action (dns/connect/etc using WAN) failed */
void mark_offline();
/* @brief Returns a guess (true or false) on whether we're online or not based on previous calls to mark_online and mark_offline */
int is_online();

/* @brief Sets hint that an auth server online action succeeded */
void mark_auth_online();
/* @brief Sets hint that an auth server online action failed */
void mark_auth_offline();
/* @brief Returns a guess (true or false) on whether we're an auth server is online or not based on previous calls to mark_auth_online and mark_auth_offline */
int is_auth_online();
void getKeyvalue(char *buf, char *reponse,char *key);//add jore
int is_mac_valid(const void *mac);
int is_ip_valid(const char *str);
int get_1dcq_system_model(char *buf);
int get_1dcq_system_version(char *buf);
/* @brief Get system info */
int get_system_info(system_info_t *buf);
int getInterface_cmd(char *buf,char *cmd,...);
int uci_set_config(const char *config, const char *section, const char *option, const char *value);
int uci_get_config(const char *config, const char *section, const char *option, char *buf);
int uci_get_cnf(const char *config, const char *section, const char *option, char *buf);
int format_mac(_OUT char *arr, _IN const char *mac, const char *del);
int id_to_mac(char *buf, char *device_id);
int get_hostname(const char *check_mac, char *name_buf);
char *curl_http_get (const char *url, unsigned long timeout);
int curl_http_get2( const char *url, unsigned long timeout, const char * outout );
char *curl_http_post (const char *url, const char *customheader, const char *data, unsigned long timeout);

/*
 * @brief Creates a human-readable paragraph of the status of wifidog
 */
char * get_status_text();
char * get_status_text_goahead();

#define LOCK_GHBN() do { \
	debug(LOG_DEBUG, "Locking wd_gethostbyname()"); \
	pthread_mutex_lock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() locked"); \
} while (0)

#define UNLOCK_GHBN() do { \
	debug(LOG_DEBUG, "Unlocking wd_gethostbyname()"); \
	pthread_mutex_unlock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() unlocked"); \
} while (0)

#endif /* _UTIL_H_ */

