/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * client_list.h
 * Original Author : cjpthree@126.com, 2015-8-8.
 *
 * Description
 */

#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_


#include <limits.h>
#include "common.h"
#include "hlist.h"
#include "list.h"


/** Counters struct for a client's bandwidth usage (in bytes)
 */
typedef struct counters_s {
    unsigned long long  incoming;	    /**< @brief Incoming data total*/
    unsigned long long  outgoing;	    /**< @brief Outgoing data total*/
    unsigned int        uplink_limit;   /**< @brief Qos uplink limit, KB per second*/
    unsigned int        downlink_limit; /**< @brief Qos uplink limit*/
    unsigned int        qos_seq;        /**< @brief Qos sequence number, for calculate mark number*/
    time_t              last_updated;	/**< @brief Last update of the counters */
} counters_t;

/** Client node for the connected client linked list.
 */
typedef struct client_s {
    struct hlist_node   hash;
    char                mac[MAC_ADDR_LEN];
    char                ip[MAX_IPV4_LEN];
    char                token[MAX_TOKEN_LEN];
    char                account[MAX_ACCOUNT_LEN];
    char                openid[MAX_TOKEN_LEN];
    char                hostname[MAX_HOST_NAME_LEN];
    int                 auth;               /* Client_auth_e */
    unsigned int        fw_state;           /* 0, 1 */
    unsigned int        tracked;            /* 0, 1 */
    int                 rssi;
    time_t              allow_time;
    time_t              duration;           /* how much seconds for allow */
    char                recent_req[MAX_RECORD_URL_LEN];
    unsigned int        dos_count;
    counters_t          counters;
} client_t;

typedef int (*CLIENT_LIST_CONDITION_FUNC)(const client_t *client, _IN void *args);
typedef int (*CLIENT_LIST_TRAVERSE_FUNC)(const client_t *client, _IN void *args);

typedef struct client_hold_s {
    dlist_head_t        list;
    client_t            client;
} client_hold_t;

typedef struct client_list_hold_s {
    dlist_head_t *head;
    unsigned int count;
    CLIENT_LIST_CONDITION_FUNC func;
    void *args;
} client_list_hold_t;


#define MAX_CLIENT_NUM          (1 << 10UL)     /* too mush would make systm slow down */

enum Client_auth_e {
    CLIENT_UNAUTH = -1,
    CLIENT_CHAOS = 0,
    CLIENT_COMMON = 1,
    CLIENT_VIP = 2,
    CLIENT_CONFIG = 3,
};

enum Client_live_time_e {
    CLIENT_LIVE_TIME_UNAUTH = (10UL),
    CLIENT_LIVE_TIME_COMMON = (30UL),
    CLIENT_LIVE_TIME_VIP = (12 * 60UL),
};

enum Client_allow_time_e {
    CLIENT_TIME_LOCAL_UNAUTH = (10UL),
    CLIENT_TIME_LOCAL_COMMON = (30UL),
    CLIENT_TIME_LOCAL_VIP = (12 * 60UL),
};

enum Client_fw_state_e {
    CLIENT_DENIED = 0,
    CLIENT_ALLOWED = 1,
};

enum Client_tracked_e {
    CLIENT_UNTRACKED = 0,
    CLIENT_TRACKED = 1,
};

enum Client_ONOFFLINE_e {
    CLIENT_OFFLINE = 0,
    CLIENT_ONLINE = 1,
};

enum Client_status_report_e {
    CLIENT_STATUS_UNREPORTED = 0,
    CLIENT_STATUS_REPORTED = 1,
};

int client_list_init();

int client_list_destory();

int client_list_get_num();

int client_list_is_exist(const char *mac);

int client_list_add(const char *mac);

int client_list_del(const char *mac);

/**
 * traverse the client list
 * @func:   process function
 * @arg:    processing mac
 * returns:
 *      -2: find invalid value
 *      -1: do func error
 *       0: success
 */
int client_list_traverse(_IN CLIENT_LIST_TRAVERSE_FUNC func, _IN _OUT void *arg);

/**
 * CCC: only use for client_list_traverse
 */
int client_list_hold(const client_t *client, client_list_hold_t *hold);
void client_list_destory_hold(client_list_hold_t *hold);
int client_list_statistics(CLIENT_LIST_CONDITION_FUNC func, void *args);

int client_list_is_connect_really(const char *mac);    /* the sole criterion of if connect or not */
/* this function can use in traverse */
#define client_is_connect_really_free_lock(client) \
    (time(NULL) - (client)->counters.last_updated < (config_get_config()->checkinterval * config_get_config()->clienttimeout))

int client_list_get_tracked(const char *mac, unsigned int *buf);
int client_list_set_tracked(const char *mac, unsigned int tracked);
int client_list_get_ip(const char *mac, char *buf);
int client_list_set_ip(const char *mac, const char *ip);
int client_list_get_token(const char *mac, char *buf);
int client_list_set_token(const char *mac, const char *token);
int client_list_get_account(const char *mac, char *buf);
int client_list_set_account(const char *mac, const char *account);
int client_list_get_openid(const char *mac, char *buf);
int client_list_set_openid(const char *mac, const char *openid);
int client_list_get_auth(const char *mac, int *buf);
int client_list_set_auth(const char *mac, int auth);
int client_list_get_fw_state(const char *mac, unsigned int *buf);
int client_list_set_fw_state(const char *mac, unsigned int fw_state);
int client_list_get_rssi(const char *mac, int *buf);
int client_list_set_rssi(const char *mac, int rssi);
int client_list_get_allow_time(const char *mac, time_t *buf);
int client_list_set_allow_time(const char *mac, time_t allow_time);
int client_list_get_duration(const char *mac, time_t *buf);
int client_list_set_duration(const char *mac, time_t duration);
int client_list_get_remain_allow_time(const char *mac, unsigned int *buf);
int client_list_get_last_updated(const char *mac, time_t *buf);
int client_list_set_last_updated(const char *mac, time_t last_updated);
int client_list_get_incoming(const char *mac, unsigned long long *buf);
int client_list_set_incoming(const char *mac, unsigned long long incoming);
int client_list_get_outgoing(const char *mac, unsigned long long *buf);
int client_list_set_outgoing(const char *mac, unsigned long long outgoing);
int client_list_get_uplink_limit(const char *mac, unsigned int *buf);
int client_list_set_uplink_limit(const char *mac, unsigned int uplink_limit);
int client_list_get_downlink_limit(const char *mac, unsigned int *buf);
int client_list_set_downlink_limit(const char *mac, unsigned int downlink_limit);
int client_list_get_qos_seq(const char *mac, unsigned int *buf);
int client_list_set_qos_seq(const char *mac, unsigned int qos_seq);
int client_list_clear_qos_seq(const char *mac);
int client_list_get_hostname(const char *mac, char *buf);
int client_list_set_hostname(const char *mac, const char *hostname);
int client_list_get_recent_req(const char *mac, char *buf);
int client_list_set_recent_req(const char *mac, const char *recent_req);
int client_list_get_client(const char *mac, client_t *buf);
int client_list_set_client(const char *mac, client_t *client_setting);
int client_list_get_dos_count(const char *mac, unsigned int *buf);
int client_list_increase_dos_count(const char *mac);
int client_list_clear_dos_count(const char *mac);
int client_list_find_mac_by_ip(_IN char *ip, _OUT char *mac);
int client_list_find_mac_by_ip_exclude(_IN const char *ip, _IN const char *mac, _OUT char *buf);
int client_list_find_mac_by_token(_IN char *token, _OUT char *mac);
int client_list_find_mac_by_openid_exclude(_IN char *openid, _IN char *mac, _OUT char *buf);
int client_list_peek(const char *mac);
int client_list_dump();
void client_list_test();
void client_list_calibration_time(void);


#endif /* _CLIENT_LIST_H_ */

