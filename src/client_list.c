/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * client_list.c
 * Original Author : cjpthree@126.com, 2015-8-8.
 *
 * Description
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <string.h>

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"
#include "common.h"
#include "hlist.h"
#include "util.h"


#define client_clist_exist()    (client_list ? 1 : 0)
#define HASH_SIZE               (1 << 7UL)
#define HASH_MASK               (HASH_SIZE - 1UL)

#define EN_CLIENT_CLEAN         1

#define CLIENT_LIST_CHECK_CAREFUL 1

static unsigned int client_num;
static pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct hlist_head client_list[HASH_SIZE];


static int client_list_peek_free_lock(const client_t *client, void *arg);
static inline client_t *client_list_search(const char *mac);
static int client_list_iterator(char *mac);
static int client_list_clean();


static inline unsigned int DJBHash(const char* str, unsigned int len, unsigned int mask)
{
    unsigned int hash = 5381;
    unsigned int i    = 0;

    for(i = 0; i < len; str++, i++) {
        hash = ((hash << 5) + hash) + (*str);
    }

    return (hash & mask);
}

static inline unsigned int BKDRCaseHash(const char* str, unsigned int len, unsigned int mask)
{
    unsigned int seed = 131; /* 31 131 1313 13131 131313 etc.. */
    unsigned int hash = 0;
    unsigned int i    = 0;

    for(i = 0; i < len; str++, i++) {
        hash = (hash * seed) + tolower(*str);
    }

    return (hash & mask);
}

int client_list_init()
{
    int i;

    pthread_mutex_lock(&client_list_mutex);
    memset(client_list, 0, sizeof(struct hlist_head) * HASH_SIZE);
    for(i = 0; i < HASH_SIZE; i++) {
        INIT_HLIST_HEAD(&client_list[i]);
    }
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_destory()
{
    int                     i;
    client_t                *tpos;
    struct hlist_node       *pos;
    struct hlist_node       *pos_tmp;

    if (!client_clist_exist()) {
        return 0;
    }

    pthread_mutex_lock(&client_list_mutex);
    for(i = 0; i < HASH_SIZE; i++) {
        hlist_for_each_entry_safe(tpos, pos, pos_tmp, &client_list[i], client_t, hash) {
            hlist_del(&tpos->hash);
            careful_free(tpos);
        }
    }
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_num()
{
    return client_num;
}

static int client_list_statistics_total_time(const client_t *client, _IN _OUT void *arg)
{
    time_t current_time = time(NULL);
    unsigned long long *total_time = arg;

    if (!client || !arg) {
        return -1;
    }

    if (client->counters.last_updated && client->auth < CLIENT_CONFIG) {
        (*total_time) += (current_time - client->counters.last_updated);
    }

    return 0;
}

static inline int client_list_clean_condition(const client_t *client, _IN void *args)
{
    time_t current_time = time(NULL);
    time_t *average_time = args;

    if (!client || !args) {
        return 0;
    }

    if (client->auth < CLIENT_CONFIG
        && !client_is_connect_really_free_lock(client)
        && (current_time - client->counters.last_updated) >= *average_time) {
        return 1;
    } else {
        return 0;
    }
}

static int client_list_clean(void)
{
    unsigned long long total_time = 0;
    time_t average_time;
    client_hold_t *pos;
    list_head_t clean_list = LIST_HEAD_INIT(clean_list);
    client_list_hold_t hold;

    if (!client_list_get_num()) {
        return 0;
    }
    debug(LOG_INFO, "start to do client list clean");

    if(client_list_traverse(client_list_statistics_total_time, &total_time)) {
        return -1;
    }
    average_time = total_time / client_list_get_num();
    debug(LOG_INFO, "average_time %lu", average_time);

    hold.func = client_list_clean_condition;
    hold.args = &average_time;
    hold.head = &clean_list;
    if (client_list_traverse((CLIENT_LIST_CONDITION_FUNC)client_list_hold, &hold)) {
        return -1;
    }

    list_for_each_entry(pos, &clean_list, client_hold_t, list) {
        debug(LOG_INFO, "delete mac %s", pos->client.mac);
        (void)client_list_del(pos->client.mac);
    }

    (void)client_list_destory_hold(&hold);
    debug(LOG_INFO, "finish to do client list clean");
    return 0;
}

/* free lock, using in this file only */
static inline client_t *client_list_search(const char *mac)
{
    unsigned int            key;
    client_t                *tpos;
    struct hlist_node       *pos;

    key = BKDRCaseHash(mac, MAC_ADDR_LEN, HASH_MASK);
    hlist_for_each_entry(tpos, pos, &client_list[key], client_t, hash) {
        if (!strncasecmp(tpos->mac, mac, MAC_ADDR_LEN)) {
            return tpos;
        }
    }

    return NULL;
}

int client_list_is_exist(const char *mac)
{
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return 0;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    if (client_list_search(mac)) {
        pthread_mutex_unlock(&client_list_mutex);
        return 1;
    }
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_add(const char *mac)
{
    unsigned int            key;
    client_t                *tpos;
    client_t                *new_node;
    struct hlist_node       *pos;

#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    key = BKDRCaseHash(mac, MAC_ADDR_LEN, HASH_MASK);
    hlist_for_each_entry(tpos, pos, &client_list[key], client_t, hash) {
        if (!strncasecmp(tpos->mac, mac, MAC_ADDR_LEN)) {
            pthread_mutex_unlock(&client_list_mutex);
            return 0;
        }
    }

    new_node = (client_t *)safe_malloc(sizeof(client_t));
    memcpy(new_node->mac, mac, MAC_ADDR_LEN); /* length must use MAC_ADDR_LEN */
    memcpy(new_node->ip, DUMY_IP, strlen(DUMY_IP) + 1);
    memcpy(new_node->token, DUMY_TOKEN, strlen(DUMY_TOKEN) + 1);
    memcpy(new_node->openid, DUMY_OPENID, strlen(DUMY_OPENID) + 1);
    memcpy(new_node->hostname, DUMY_HOST_NAME, strlen(DUMY_HOST_NAME) + 1);
    memcpy(new_node->recent_req, DUMY_REQ_URL, strlen(DUMY_REQ_URL) + 1);
    new_node->auth = CLIENT_CHAOS;
    new_node->fw_state = CLIENT_DENIED;
    new_node->tracked = CLIENT_UNTRACKED;
    new_node->counters.incoming = 0;
    new_node->counters.outgoing = 0;
    new_node->counters.uplink_limit = 0;
    new_node->counters.downlink_limit = 0;
    new_node->counters.qos_seq = 0;
    new_node->counters.last_updated = 0;
    new_node->dos_count = 0;
    new_node->allow_time = 0;
    hlist_add_head(&new_node->hash, &client_list[key]);
    client_num++;
    pthread_mutex_unlock(&client_list_mutex);
    debug(LOG_DEBUG, "add [%s] to client list", mac);

#if EN_CLIENT_CLEAN
    if (client_list_get_num() >= MAX_CLIENT_NUM) {
        (void)client_list_clean();
    }
#endif
    return 0;
}

int client_list_del(const char *mac)
{
    unsigned int            key;
    client_t                *tpos;
    struct hlist_node       *pos;
    struct hlist_node       *pos_tmp;

#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    key = BKDRCaseHash(mac, MAC_ADDR_LEN, HASH_MASK);
    hlist_for_each_entry_safe(tpos, pos, pos_tmp, &client_list[key], client_t, hash) {
        if (!strncasecmp(tpos->mac, mac, MAC_ADDR_LEN)) {
            hlist_del(&tpos->hash);
            careful_free(tpos);
            client_num--;
            pthread_mutex_unlock(&client_list_mutex);
            debug(LOG_DEBUG, "found [%s] in client list, del", mac);
            return 0;
        }
    }
    pthread_mutex_unlock(&client_list_mutex);

    debug(LOG_DEBUG, "can not find [%s] in client list", mac);
    return -1;
}

/**
 * the iterator of client list, getting next mac
 * @mac: input the current mac, and get the next mac. input (strlen(mac) == 0) can get first mac
 * attention:   can not change list's struct before all iterator calls finish.
 *              free lock, using this file only.
 * returns:
 *      -1. fail
 *       0. success
 *       1. end
 */
static int client_list_iterator(char *mac)
{
    int                     i;
    client_t                *tpos;
    struct hlist_node       *pos;
    unsigned int            key;
    int                     found = 0;

    if (!strlen(mac)) {
        for(i = 0; i < HASH_SIZE; i++) {
            hlist_for_each_entry(tpos, pos, &client_list[i], client_t, hash) {
                memcpy(mac, tpos->mac, MAC_ADDR_LEN);
                return 0;
            }
        }
    } else {
        key = BKDRCaseHash(mac, MAC_ADDR_LEN, HASH_MASK);
        for(i = key; i < HASH_SIZE; i++) {
            hlist_for_each_entry(tpos, pos, &client_list[i], client_t, hash) {
                if (!strncasecmp(mac, tpos->mac, MAC_ADDR_LEN)) {
                    found = 1;
                    continue;
                }
                if (found && strncasecmp(mac, tpos->mac, MAC_ADDR_LEN)) {
                    memcpy(mac, tpos->mac, MAC_ADDR_LEN);
                    return 0;
                }
            }
        }
    }

    memset(mac, 0, MAC_ADDR_LEN);
    return 1; /* finish, but not found any mac */
}

/**
 * traverse the client list
 * @func:   process function, CCC:can not call client list funcion in func, or will be make deadlock
 * @arg:    processing mac
 * returns:
 *      -2: find invalid value
 *      -1: do func error
 *       0: success
 */
int client_list_traverse(_IN CLIENT_LIST_CONDITION_FUNC func, _IN _OUT void *arg)
{
    char mac[MAC_ADDR_LEN] = {0};
    client_t *p_find_client;
    int ret;

    if (!func
#if CLIENT_LIST_CHECK_CAREFUL
        || !client_clist_exist()
#endif
        ) {
        return -1;
    }

    pthread_mutex_lock(&client_list_mutex);
    for ( ; !client_list_iterator(mac); ) {
        if (!is_mac_valid(mac)) {
            debug(LOG_ERR, "find invalid mac in client list");
            return -2;
        }
        p_find_client = client_list_search(mac);
        if (!p_find_client) {
            debug(LOG_ERR, "fail to iterator because of invalid mac");
            return -2;
        }
        ret = func(p_find_client, arg);
        if (ret < 0) {
            pthread_mutex_unlock(&client_list_mutex);
            return -1;
        } else if (ret > 0) { /* found it */
            pthread_mutex_unlock(&client_list_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_hold(const client_t *client, client_list_hold_t *hold)
{
    client_hold_t *new_node;
    list_head_t *head;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client || !hold || !hold->head) {
        return -1;
    }
#endif

    head = hold->head;

    if (hold->func) {
        /* compare false */
        if (!(hold->func(client, hold->args))) {
            return 0;
        }
    }

    new_node = (client_hold_t *)safe_malloc(sizeof(client_hold_t));
    memcpy(&new_node->client, client, sizeof(client_t));
    list_add(&new_node->list, head);

    return 0;
}

void client_list_destory_hold(client_list_hold_t *hold)
{
    client_hold_t *pos;
    client_hold_t *pos_tmp;
    list_head_t *head;

#if CLIENT_LIST_CHECK_CAREFUL
    if (!hold || !hold->head) {
        return;
    }
#endif

    head = hold->head;

    list_for_each_entry_safe(pos, pos_tmp, head, client_hold_t, list) {
        list_del(&pos->list);
        careful_free(pos);
    }
}

static int client_list_statistics_count(const client_t *client, client_list_hold_t *hold)
{
    if (hold->func) {
        if ((hold->func(client, hold->args)) == 1) {
            hold->count++;  /* compare accord */
        }
    }

    return 0;
}

/* return count that accord the incomming func */
int client_list_statistics(CLIENT_LIST_CONDITION_FUNC func, void *args)
{
    client_list_hold_t hold;

#if _CHECK_CAREFUL_
        if (!func) {
            return 0;
        }
#endif
    
    memset(&hold, 0, sizeof(client_list_hold_t));
    hold.func = func;
    hold.args = args;
    if(client_list_traverse((CLIENT_LIST_CONDITION_FUNC)client_list_statistics_count, &hold)) {
        return 0;
    }
    
    return hold.count;
}

int client_list_is_connect_really(const char *mac)
{
    time_t last_updated;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return 0;
    }
#endif

    if(client_list_get_last_updated(mac, &last_updated)) {
        return 0;
    }

    return (time(NULL) - last_updated < (config_get_config()->checkinterval * config_get_config()->clienttimeout));
}

int client_list_get_ip(const char *mac, char *buf)
{
    client_t *client;

#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(buf, client->ip, strlen(client->ip) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_ip(const char *mac, const char *ip)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !ip || !client_clist_exist() || !is_mac_valid(mac) || !is_ip_valid(ip)) {
        return -1;
    }
    if (strlen(ip) >= MAX_IPV4_LEN) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(client->ip, ip, strlen(ip) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_token(const char *mac, char *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(buf, client->token, strlen(client->token) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_token(const char *mac, const char *token)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !token || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
    if (strlen(token) >= MAX_TOKEN_LEN) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(client->token, token, strlen(token) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_openid(const char *mac, char *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(buf, client->openid, strlen(client->openid) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_openid(const char *mac, const char *openid)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !openid || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
    if (strlen(openid) >= MAX_OPENID_LEN) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(client->openid, openid, strlen(openid) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_auth(const char *mac, int *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->auth;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_auth(const char *mac, int auth)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    client->auth = auth;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_fw_state(const char *mac, unsigned int *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->fw_state;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_fw_state(const char *mac, unsigned int fw_state)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    client->fw_state = fw_state;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_allow_time(const char *mac, time_t *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->allow_time;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_allow_time(const char *mac, time_t allow_time)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    client->allow_time = allow_time;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_remain_allow_time(const char *mac, unsigned int *buf)
{
    client_t *client;
    time_t	current_time = time(NULL);
    int remain = 0;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }

    if (client->allow_time /* && client->fw_state == CLIENT_ALLOWED*/) {
        if (client->auth >= CLIENT_VIP) {
            remain = (CLIENT_TIME_LOCAL_WECHAT_VIP * config_get_config()->checkinterval - (current_time - client->allow_time));
        } else if (client->auth >= CLIENT_COMMON) {
            remain = (CLIENT_TIME_LOCAL_WECHAT_COMMON * config_get_config()->checkinterval - (current_time - client->allow_time));
        } else {
            remain = (CLIENT_TIME_LOCAL_WECHAT_UNAUTH * config_get_config()->checkinterval - (current_time - client->allow_time));
        }
    }

    if (remain < 0) {
        *buf = 0;
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    } else {
        *buf = remain;
        pthread_mutex_unlock(&client_list_mutex);
        return 0;
    }
    
    pthread_mutex_unlock(&client_list_mutex);
    return 0;
}

int client_list_get_tracked(const char *mac, unsigned int *buf)
{
    client_t *client;

#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->tracked;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_tracked(const char *mac, unsigned int tracked)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    client->tracked = tracked;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_last_updated(const char *mac, time_t *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->counters.last_updated;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_last_updated(const char *mac, time_t last_updated)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    client->counters.last_updated = last_updated;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_incoming(const char *mac, unsigned long long *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->counters.incoming;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_incoming(const char *mac, unsigned long long incoming)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    client->counters.incoming = incoming;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_outgoing(const char *mac, unsigned long long *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->counters.outgoing;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_outgoing(const char *mac, unsigned long long outgoing)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        debug(LOG_INFO, "can not find mac %s", mac);
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    }
    client->counters.outgoing = outgoing;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_uplink_limit(const char *mac, unsigned int *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->counters.uplink_limit;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_uplink_limit(const char *mac, unsigned int uplink_limit)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        debug(LOG_INFO, "can not find mac %s", mac);
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    }
    client->counters.uplink_limit = uplink_limit;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_downlink_limit(const char *mac, unsigned int *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->counters.downlink_limit;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_downlink_limit(const char *mac, unsigned int downlink_limit)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        debug(LOG_INFO, "can not find mac %s", mac);
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    }
    client->counters.downlink_limit = downlink_limit;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_qos_seq(const char *mac, unsigned int *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->counters.qos_seq;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_qos_seq(const char *mac, unsigned int qos_seq)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        debug(LOG_INFO, "can not find mac %s", mac);
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    }
    client->counters.qos_seq = qos_seq;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_clear_qos_seq(const char *mac)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        debug(LOG_INFO, "can not find mac %s", mac);
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    }
    client->counters.qos_seq = 0;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_hostname(const char *mac, char *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(buf, client->hostname, strlen(client->hostname) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_hostname(const char *mac, const char *hostname)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !hostname || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
    if (strlen(hostname) >= MAX_HOST_NAME_LEN) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        debug(LOG_INFO, "can not find mac %s", mac);
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    }
    memcpy(client->hostname, hostname, strlen(hostname) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_recent_req(const char *mac, char *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(buf, client->recent_req, strlen(client->recent_req) + 1);
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_recent_req(const char *mac, const char *recent_req)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !recent_req || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        debug(LOG_INFO, "can not find mac %s", mac);
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    }
    if (strlen(recent_req) >= MAX_RECORD_URL_LEN) {
        memcpy(client->recent_req, recent_req, MAX_RECORD_URL_LEN - 1);;
    } else {
        memcpy(client->recent_req, recent_req, strlen(recent_req) + 1);
    }
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}


int client_list_get_client(const char *mac, client_t *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    memcpy(buf, client, sizeof(client_t));
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_set_client(const char *mac, client_t *client_setting)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_setting || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        debug(LOG_INFO, "can not find mac %s", mac);
        pthread_mutex_unlock(&client_list_mutex);
        return -1;
    }
    memcpy(client->ip, client_setting->ip, sizeof(client_t) - offsetof(client_t, ip));
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_get_dos_count(const char *mac, unsigned int *buf)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !buf || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    *buf = client->dos_count;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_increase_dos_count(const char *mac)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    client->dos_count += 1;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

int client_list_clear_dos_count(const char *mac)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!mac || !client_clist_exist() || !is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_INFO, "can not find mac %s", mac);
        return -1;
    }
    client->dos_count = 0;
    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

static int client_list_ip_to_mac(const client_t *client,  _IN _OUT void *arg)
{
    char *ip = arg;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client || !is_ip_valid(ip)) {
        return -1;
    }
#endif

    if (!strncmp(client->ip, ip, strlen(ip) + 1)) {
        memset(arg, 0, strlen(arg) + 1);
        memcpy(arg, client->mac, MAC_ADDR_LEN);
        return 1;
    }

    return 0;
}

static int client_list_token_to_mac(const client_t *client,  _IN _OUT void *arg)
{
    char *token = arg;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client || !token) {
        return -1;
    }
#endif

    if (!strncasecmp(client->token, token, strlen(client->token) + 1)) {
        memset(arg, 0, strlen(arg) + 1);
        memcpy(arg, client->token, MAX_TOKEN_LEN);
        return 1;
    }

    return 0;
}

int client_list_find_mac_by_ip(_IN char *ip, _OUT char *mac)
{
    client_t *client;
    char buf[MAC_ADDR_LEN];
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client_clist_exist() || !is_ip_valid(ip)) {
        return -1;
    }
#endif

    if (!strncmp(ip, DUMY_IP, strlen(DUMY_IP) + 1)) {
        debug(LOG_ERR, "can not using dumy ip %s", DUMY_IP);
        return -1;
    }

    memset(buf, 0, sizeof(buf) / sizeof(buf[0]));
    memcpy(buf, ip, strlen(ip));
    if (client_list_traverse(client_list_ip_to_mac, buf)) {
        debug(LOG_INFO, "can not get mac using ip %s", ip);
        return -1;
    }

    if (!is_mac_valid(buf)) {
        debug(LOG_INFO, "can not get mac using ip %s", ip);
        return -1;
    }

    memcpy(mac, buf, MAC_ADDR_LEN);

    return 0;
}

typedef struct find_s {
    char ip[MAX_IPV4_LEN];
    char openid[MAX_OPENID_LEN];
    char exclude_mac[MAC_ADDR_LEN];
    char _OUT buf[MAC_ADDR_LEN];
} find_t;

static int client_list_ip_to_mac_exclude(const client_t *client,  _IN _OUT find_t *arg)
{
    if (!strncasecmp(client->ip, arg->ip, strlen(arg->ip) + 1)
        && strncasecmp(arg->exclude_mac, client->mac, MAC_ADDR_LEN)) {
        memcpy(arg->buf, client->mac, MAC_ADDR_LEN);
        return 1;
    }

    return 0;
}

int client_list_find_mac_by_ip_exclude(_IN char *ip, _IN char *mac, _OUT char *buf)
{
    client_t *client;
    find_t find_arg;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!is_mac_valid(mac) || !buf || !client_clist_exist() || !is_ip_valid(ip)) {
        return -1;
    }
#endif

    if (!strncmp(ip, DUMY_IP, strlen(DUMY_IP) + 1)) {
        debug(LOG_ERR, "can not using dumy ip %s", DUMY_IP);
        return -1;
    }

    memset(&find_arg, 0, sizeof(find_t));
    memcpy(find_arg.ip, ip, strlen(ip));
    memcpy(find_arg.exclude_mac, mac, MAC_ADDR_LEN);
    if (client_list_traverse((CLIENT_LIST_CONDITION_FUNC)client_list_ip_to_mac_exclude, &find_arg)) {
        debug(LOG_DEBUG, "can not get mac using ip %s", ip);
        return -1;
    }

    if (!is_mac_valid(find_arg.buf)) {
        debug(LOG_DEBUG, "can not get mac using ip %s", ip);
        return -1;
    }

    memcpy(buf, find_arg.buf, MAC_ADDR_LEN);

    return 0;
}

int client_list_find_mac_by_token(_IN char *token, _OUT char *mac)
{
    client_t *client;
    char buf[MAX_TOKEN_LEN];
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client_clist_exist() || !token) {
        return -1;
    }
#endif

    memset(buf, 0, sizeof(buf) / sizeof(buf[0]));
    memcpy(buf, token, strlen(token));
    if (client_list_traverse(client_list_token_to_mac, buf)) {
        debug(LOG_INFO, "can not get mac using token %s", token);
        return -1;
    }

    if (!is_mac_valid(buf)) {
        debug(LOG_INFO, "can not get mac using token %s", token);
        return -1;
    }

    memcpy(mac, buf, MAC_ADDR_LEN);

    return 0;
}

static int client_list_openid_to_mac_exclude(const client_t *client,  _IN _OUT find_t *arg)
{
    if (!strncasecmp(client->openid, arg->openid, strlen(arg->openid) + 1)
        && strncasecmp(arg->exclude_mac, client->mac, MAC_ADDR_LEN)) {
        memcpy(arg->buf, client->mac, MAC_ADDR_LEN);
        return 1;
    }

    return 0;
}

int client_list_find_mac_by_openid_exclude(_IN char *openid, _IN char *mac, _OUT char *buf)
{
    client_t *client;
    find_t find_arg;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!is_mac_valid(mac) || !buf || !client_clist_exist() || !openid) {
        return -1;
    }
#endif

    if (!strncmp(openid, DUMY_OPENID, strlen(DUMY_OPENID) + 1)) {
        debug(LOG_ERR, "can not using dumy openid %s", DUMY_OPENID);
        return -1;
    }

    memset(&find_arg, 0, sizeof(find_t));
    memcpy(find_arg.openid, openid, strlen(openid));
    memcpy(find_arg.exclude_mac, mac, MAC_ADDR_LEN);
    if (client_list_traverse((CLIENT_LIST_CONDITION_FUNC)client_list_openid_to_mac_exclude, &find_arg)) {
        debug(LOG_DEBUG, "can not get mac using openid %s", openid);
        return -1;
    }

    if (!is_mac_valid(find_arg.buf)) {
        debug(LOG_DEBUG, "can not get mac using openid %s", openid);
        return -1;
    }

    memcpy(buf, find_arg.buf, MAC_ADDR_LEN);

    return 0;
}

int client_list_peek(const char *mac)
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client_clist_exist()) {
        return -1;
    }
#endif

    pthread_mutex_lock(&client_list_mutex);
    client = client_list_search(mac);
    if (!client) {
        pthread_mutex_unlock(&client_list_mutex);
        debug(LOG_ERR, "can not find this mac");
        return -1;
    }

    printf("IP: %s MAC: %s Token: %s Auth: %d Fw_state: %u Tracked: %u\n",
        client->ip, client->mac, client->token,
        client->auth, client->fw_state, client->tracked);
    printf("Incoming: %llu Outgoing: %llu Last_updated: %lu\n" ,
        client->counters.incoming, client->counters.outgoing,
        client->counters.last_updated);
    printf("dos_count: %u\n" , client->dos_count);

    pthread_mutex_unlock(&client_list_mutex);

    return 0;
}

static int client_list_peek_free_lock(const client_t *client, void *arg)
{    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client || !client_clist_exist()) {
        return -1;
    }
#endif

    printf("IP: %s MAC: %s Token: %s Auth: %d Fw_state: %u Tracked: %u\n",
        client->ip, client->mac, client->token,
        client->auth, client->fw_state, client->tracked);
    printf("Incoming: %llu Outgoing: %llu Last_updated: %lu\n" ,
        client->counters.incoming, client->counters.outgoing,
        client->counters.last_updated);
    printf("dos_count: %u\n" , client->dos_count);

    return 0;
}

int client_list_dump()
{
    client_t *client;
    
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client_clist_exist()) {
        return -1;
    }
#endif

    client_list_traverse(client_list_peek_free_lock, NULL);

    return 0;
}

static int client_list_calibration_time_free_lock(const client_t *client_in, void *arg)
{
    time_t current_time = time(NULL);
    client_t *client = (client_t *)client_in;

#if CLIENT_LIST_CHECK_CAREFUL
    if (!client || !client_clist_exist()) {
        return -1;
    }
#endif

    if (client->counters.last_updated && client->counters.last_updated < MINIMUM_STARTED_TIME) {
        client->counters.last_updated = current_time - client->counters.last_updated;
    }

    if (client->allow_time && client->allow_time < MINIMUM_STARTED_TIME) {
        client->allow_time = current_time - client->allow_time;
    }

    return 0;
}

void client_list_calibration_time(void)
{
    client_t *client;
        
#if CLIENT_LIST_CHECK_CAREFUL
    if (!client_clist_exist()) {
        return;
    }
#endif

    client_list_traverse(client_list_calibration_time_free_lock, NULL);

    return;
}

void client_list_test()
{
    int i , j;
    client_t *client;
    char buf_ip[MAX_IPV4_LEN] = {0};
    char buf_token[MAX_TOKEN_LEN] = {0};
    unsigned long last_updated;
    unsigned long long incoming;
    unsigned long long outgoing;
    int auth;
    unsigned int fw_state;
    char *ip = "192.168.10.233";
    char *token = "8247867720150716091888";
    char mac[][MAC_ADDR_LEN] = {
        "00:00:00:00:00:00",
        "00:00:00:00:00:01",
        "00:00:00:00:00:02",
        "00:00:00:00:00:03",
        "00:00:00:00:00:04",
        "00:00:00:00:00:05",
        "00:00:00:00:00:06",
        "00:00:00:00:00:07",
        "00:00:00:00:00:08",
        "00:00:00:00:00:09",
        "00:00:00:00:00:0A",
        "00:00:00:00:00:0b",};

    client_list_add(mac[0]);
    client_list_set_last_updated(mac[0], time(NULL));
    client_list_peek(mac[0]);
    sleep(1);
    client_list_add(mac[1]);
    client_list_set_last_updated(mac[1], time(NULL));
    client_list_peek(mac[1]);
    sleep(1);
    client_list_add(mac[2]);
    client_list_set_last_updated(mac[2], time(NULL));
    client_list_peek(mac[2]);
    sleep(1);
    client_list_add(mac[3]);
    client_list_set_last_updated(mac[3], time(NULL));
    client_list_peek(mac[3]);
    sleep(1);
    client_list_add(mac[4]);
    client_list_set_last_updated(mac[4], time(NULL));
    client_list_peek(mac[4]);
    sleep(1);
    client_list_add(mac[6]);
    client_list_set_last_updated(mac[6], time(NULL));
    client_list_peek(mac[6]);
    sleep(1);
    client_list_add(mac[7]);
    client_list_set_last_updated(mac[7], time(NULL));
    client_list_peek(mac[7]);
    sleep(1);
    client_list_add(mac[8]);
    client_list_set_last_updated(mac[8], time(NULL));
    client_list_peek(mac[8]);
    sleep(1);
    client_list_add(mac[9]);
    client_list_set_last_updated(mac[9], time(NULL));
    client_list_peek(mac[9]);
    sleep(1);
    client_list_add(mac[10]);
    client_list_set_last_updated(mac[10], time(NULL));
    client_list_peek(mac[10]);
    sleep(1);
    client_list_add(mac[11]);
    client_list_set_last_updated(mac[11], time(NULL));
    client_list_peek(mac[11]);
    sleep(1);
    client_list_add(mac[12]);
    client_list_set_last_updated(mac[12], time(NULL));
    client_list_peek(mac[12]);

    client_list_dump();

    client_list_clean();
    client_list_dump();

    for (i = 0; i < sizeof(mac) / sizeof(mac[0]); i++) {
        if (!client_list_is_exist(mac[i])) {
            debug(LOG_ERR, "can not find %s", mac[i]);
        }
    }

    for (i = 0; i < sizeof(mac) / sizeof(mac[0]); i++) {
        client_list_del(mac[i]);
    }
    client_list_dump();

    for (i = 0; i < sizeof(mac) / sizeof(mac[0]); i++) {
        client_list_add(mac[i]);
    }
    client_list_dump();

    for (i = 0; i < sizeof(mac) / sizeof(mac[0]); i++) {
        if (!client_list_is_exist(mac[i])) {
            debug(LOG_ERR, "can not find %s", mac[i]);
        }
    }

    for (i = 0; i < sizeof(mac) / sizeof(mac[0]); i++) {
        client_list_get_ip(mac[i], buf_ip);
        client_list_get_token(mac[i], buf_token);
        client_list_get_auth(mac[i], &auth);
        client_list_get_fw_state(mac[i], &fw_state);
        client_list_get_last_updated(mac[i], &last_updated);
        client_list_get_incoming(mac[i], &incoming);
        client_list_get_outgoing(mac[i], &outgoing);
        debug(LOG_ERR, "get mac %s, ip %s, token %s, auth %d, fw_state %d, last_updated %lu, incoming %llu, outgoing %llu",
            mac[i], buf_ip, buf_token, auth, fw_state, last_updated, incoming, outgoing);
    }

    sleep(1);
    i = 0;
    client_list_set_ip(mac[i], "192.168.1.111");
    client_list_set_token(mac[i], "1111");
    client_list_set_auth(mac[i], 1);
    client_list_set_fw_state(mac[i], 1);
    client_list_set_last_updated(mac[i], time(NULL));
    client_list_set_incoming(mac[i], 1111);
    client_list_set_outgoing(mac[i], 1112);

    i = 1;
    if(client_list_set_ip(mac[i], "0.0.0.0")) {
        debug(LOG_ERR, "fail to set ip 0.0.0.0");
    }
    if(client_list_set_token(mac[i], "0")) {
        debug(LOG_ERR, "fail to set token 0");
    }
    client_list_set_auth(mac[i], 0);
    client_list_set_fw_state(mac[i], 0);
    client_list_set_last_updated(mac[i], 0);
    client_list_set_incoming(mac[i], 0);
    client_list_set_outgoing(mac[i], 0);

    i = 2;
    client_list_set_ip(mac[i], "192.168.1.222");
    client_list_set_token(mac[i], "2222");
    client_list_set_auth(mac[i], 3);
    client_list_set_fw_state(mac[i], 1);
    client_list_set_last_updated(mac[i], time(NULL));
    client_list_set_incoming(mac[i], 2221);
    client_list_set_outgoing(mac[i], 2222);

    debug(LOG_ERR, "after set");
    client_list_dump();

    debug(LOG_ERR, "test efficiency i = 1000, now %llu", time(NULL));
    i = 7;
    for (j = 0; j < 1; j++) {
        client_list_add(mac[i]);

        client_list_get_ip(mac[i], buf_ip);
        client_list_get_token(mac[i], buf_token);
        client_list_get_auth(mac[i], &auth);
        client_list_get_fw_state(mac[i], &fw_state);
        client_list_get_last_updated(mac[i], &last_updated);
        client_list_get_incoming(mac[i], &incoming);
        client_list_get_outgoing(mac[i], &outgoing);

        client_list_set_ip(mac[i], "192.168.1.222");
        client_list_set_token(mac[i], "2222");
        client_list_set_auth(mac[i], 3);
        client_list_set_fw_state(mac[i], 1);
        client_list_set_last_updated(mac[i], time(NULL));
        client_list_set_incoming(mac[i], 2221);
        client_list_set_outgoing(mac[i], 2222);

        client_list_del(mac[i]);
    }
    debug(LOG_ERR, "test complete i = 1000, now %llu", time(NULL));
}

