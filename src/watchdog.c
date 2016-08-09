/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * watchdog.c
 * Original Author : cjpthree@126.com, 2015-7-31.
 *
 * Description
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#ifdef __OPENWRT__
#include <uci.h>
#endif

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "util.h"
#include "watchdog.h"
#include "list.h"
#include "fw_backup.h"
#include "client_record_backup.h"


pthread_cond_t          watchdog_thread_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t         watchdog_thread_cond_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct pthread_watchdog_node_s {
    char *name;
    struct list_head list;
    time_t	feed_time;
    int timeout_count;
} pthread_watchdog_node_t;

LIST_HEAD(pthread_watchdog_list);
pthread_mutex_t pthread_watchdog_list_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef enum {
    POLICY_ACCEPT = 0,
    POLICY_DROP,
    POLICY_REJECT,
    POLICY_UNKOWN
} Iptable_policy_e;

#define CHAIN_INPUT_NAME    "INPUT"
#define CHAIN_FORWARE_NAME  "FORWARD"
#define CHAIN_OUTPUT_NAME   "OUTPUT"
#define POLICY_ACCEPT_VALUE "ACCEPT"
#define POLICY_DROP_VALUE   "DROP"
#define POLICY_REJECT_VALUE "REJECT"

static int get_iptables_policy(Iptable_policy_e *p_policy, char *reponse, char *chain)
{
    char buf[MAX_BUF];
    char *key = NULL;

    if (!p_policy || !reponse || !chain) {
        return -1;
    }

    memset(buf, 0, sizeof(buf) / sizeof(buf[0]));

    if (!memcmp(chain, CHAIN_INPUT_NAME, strlen(CHAIN_INPUT_NAME) + 1)) {
        key = "Chain INPUT";
    } else if (!memcmp(chain, CHAIN_FORWARE_NAME, strlen(CHAIN_FORWARE_NAME) + 1)) {
        key = "Chain FORWARD";
    } else if (!memcmp(chain, CHAIN_OUTPUT_NAME, strlen(CHAIN_OUTPUT_NAME) + 1)) {
        key = "Chain OUTPUT";
    } else {
        debug(LOG_ERR, "can not find chain %s", chain);
        return -1;
    }

    getKeyvalue(buf, reponse, key);
    if (strstr(buf, POLICY_ACCEPT_VALUE)) {
        *p_policy = POLICY_ACCEPT;
    } else if (strstr(buf, POLICY_DROP_VALUE)) {
        *p_policy = POLICY_DROP;
    } else if (strstr(buf, POLICY_REJECT_VALUE)) {
        *p_policy = POLICY_REJECT;
    } else {
        debug(LOG_DEBUG, "chain %s policy unkown", chain);
        *p_policy = POLICY_UNKOWN;
    }

    return 0;
}

static int is_fw_policy_right()
{
    char result[POPEN_MAX_BUF];
#if IPTABELES_VESION > (1421)
    const char *script = "iptables -L -n -w";
#else
    const char *script = "iptables -L -n";
#endif
    int i;
    Iptable_policy_e policy;
    int retry = 0;

    while (memset(result, 0, POPEN_MAX_BUF), execute_cmd(script, result) != 0 && ++retry < RETRY_MAX_TIME) {
        sleep(1);
    }
    if (retry >=RETRY_MAX_TIME) {
        debug(LOG_ERR, "run command %s failed", script);
        return -1;
    }

    result[POPEN_MAX_BUF - 1] = '\0';
    if (strlen(result)) {
        if (get_iptables_policy(&policy, result, CHAIN_INPUT_NAME)) {
            debug(LOG_ERR, "get %s policy failed", CHAIN_INPUT_NAME);
            return -1;
        }
        if (policy == POLICY_DROP) {
            debug(LOG_DEBUG, "chain %s is policy %s", CHAIN_INPUT_NAME, POLICY_DROP_VALUE);
            return 0;
        }

        if (get_iptables_policy(&policy, result, CHAIN_OUTPUT_NAME)) {
            debug(LOG_ERR, "get %s policy failed", CHAIN_OUTPUT_NAME);
            return -1;
        }
        if (policy == POLICY_DROP) {
            debug(LOG_DEBUG, "chain %s is policy %s", CHAIN_INPUT_NAME, POLICY_DROP_VALUE);
            return 0;
        }
    }

    return 1;
}

static int is_fw_nat_seting_right()
{
    char result[POPEN_MAX_BUF];
#if IPTABELES_VESION > (1421)
    const char *script = "iptables -L -n -t nat -w";
#else
    const char *script = "iptables -L -n -t nat";
#endif
    int i;
    Iptable_policy_e policy;
    int retry = 0;

    while (memset(result, 0, POPEN_MAX_BUF), execute_cmd(script, result) != 0 && ++retry < RETRY_MAX_TIME) {
        sleep(1);
    }
    if (retry >=RETRY_MAX_TIME) {
        debug(LOG_ERR, "run command %s failed", script);
        return -1;
    }

    result[POPEN_MAX_BUF - 1] = '\0';
    if (strlen(result)) {
        if (!strstr(result, "delegate_postrouting")) { /* sometimes fw init fail, and can not find this rule, then network go wrong */
            debug(LOG_ERR, "can not find delegate_postrouting chain in nat table");
            return 0;
        }
    }

    return 1;
}

static int is_fw_seting_right()
{
    int ret;

    ret = is_fw_policy_right();
    if (ret <= 0) {
        return ret;
    }

    ret = is_fw_nat_seting_right();
    if (ret <= 0) {
        return ret;
    }

    return 1;
}

int is_network_welldone()
{
    int ret;

    if (is_fw_seting_right() <= 0) {
        ret = 0;
    } else {
        ret = 1;
    }

    return ret;
}

void network_restart()
{
#ifdef __OPENWRT__
    execute_cmd("/etc/init.d/network restart", NULL);
#endif
#ifdef __MTK_SDK__
    execute_cmd("internet.sh", NULL);
#endif
}

/*************************************** pthread watchdog **********************************************************/

static inline pthread_watchdog_node_t *pthread_watchdog_search_list(char *name)
{
    pthread_watchdog_node_t              *tpos;

    list_for_each_entry(tpos, &pthread_watchdog_list, pthread_watchdog_node_t, list) {
        if (!strncmp(tpos->name, name, strlen(tpos->name))) {
            return tpos;
        }
    }

    return NULL;
}

void pthread_watchdog_dump_list()
{
    pthread_watchdog_node_t              *tpos;

    list_for_each_entry(tpos, &pthread_watchdog_list, pthread_watchdog_node_t, list) {
        printf("name %s, feed time %ld\n", tpos->name, tpos->feed_time);
    }
    debug(LOG_ERR, "dump end");
}


int pthread_watchdog_is_exist(char *name)
{
    if (!name) {
        return 0;
    }

    pthread_mutex_lock(&pthread_watchdog_list_mutex);
    if (pthread_watchdog_search_list(name)) {
        pthread_mutex_unlock(&pthread_watchdog_list_mutex);
        return 1;
    }
    pthread_mutex_unlock(&pthread_watchdog_list_mutex);

    return 0;
}

static void pthread_watchdog_init_list(void)
{
    /* need not do any thing */
}

static void pthread_watchdog_destory_list(void)
{
    struct list_head *pos, *ptmp;
    pthread_watchdog_node_t *pos_node;

    pthread_mutex_lock(&pthread_watchdog_list_mutex);
    list_for_each_safe(pos, ptmp, &pthread_watchdog_list) {
        pos_node = list_entry(pos, pthread_watchdog_node_t, list);
        list_del(pos);
        careful_free(pos_node->name);
        careful_free(pos_node);
    }
    pthread_mutex_unlock(&pthread_watchdog_list_mutex);
}

void restart_system()
{
    execute_cmd("reboot", NULL);
}

int pthread_watchdog_register(char *name)
{
    pthread_watchdog_node_t *new_node;

    if (!name) {
        return -1;
    }

    pthread_mutex_lock(&pthread_watchdog_list_mutex);
    if (pthread_watchdog_search_list(name)) {
        debug(LOG_ERR, "%s is used by other pthread", name);
        pthread_mutex_unlock(&pthread_watchdog_list_mutex);
        return -1;
    }

    new_node = (pthread_watchdog_node_t *)safe_malloc(sizeof(pthread_watchdog_node_t));
    new_node->name = safe_strdup(name);
    new_node->feed_time = time(NULL);
    new_node->timeout_count = 0;
    list_add(&new_node->list, &pthread_watchdog_list);
    pthread_mutex_unlock(&pthread_watchdog_list_mutex);

    return 0;
}

int _watchdog_feed_(char *name)
{
    pthread_watchdog_node_t *feed_node;

    if (!name) {
        return -1;
    }

    pthread_mutex_lock(&pthread_watchdog_list_mutex);
    feed_node = pthread_watchdog_search_list(name);
    if (!feed_node) {
        debug(LOG_ERR, "can not find pthread %s", name);
        pthread_mutex_unlock(&pthread_watchdog_list_mutex);
        return -1;
    }
    debug(LOG_DEBUG, "%s feedding dog", name);
    feed_node->feed_time = time(NULL);
    pthread_mutex_unlock(&pthread_watchdog_list_mutex);

    return 0;
}

static int is_pthreads_welldone()
{
    pthread_watchdog_node_t              *tpos;
    time_t	current_time=time(NULL);
    int checkinterval = config_get_config()->checkinterval;
    int timeout = config_get_config()->threadWatchdogTimeout;

    pthread_mutex_lock(&pthread_watchdog_list_mutex);
    list_for_each_entry(tpos, &pthread_watchdog_list, pthread_watchdog_node_t, list) {
        if (current_time - tpos->feed_time >= checkinterval * timeout) {
            /* because of time sever stoping when shutdown, it will timeout usually firsttime */
            if (0 == tpos->timeout_count) {
                tpos->timeout_count += 1;
                pthread_mutex_unlock(&pthread_watchdog_list_mutex);
                return 1;
            }
            debug(LOG_ERR, "pthread %s timeout, over %lu seconds(timeout %lu)",
                tpos->name, current_time - tpos->feed_time - timeout * checkinterval, checkinterval * timeout);
            pthread_mutex_unlock(&pthread_watchdog_list_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&pthread_watchdog_list_mutex);

    return 1;
}

static void cmm_watchdog(void)
{
    int restart_network = 0;
    static time_t last_refresh_time;
    time_t current_time = time(NULL);

#if OPEN_CHECK_NETWORK
    /* If network is wrong, then restart network.
    * If still wrong, then ignore
    * It would be found network can work again next request cycle
    */
    while (!is_network_welldone() && ++restart_network < RETRY_MAX_TIME) {
        debug(LOG_ERR, "network need to restart, retry time %d", restart_network);
        network_restart();
        sleep(5);
    }
    if (restart_network >= RETRY_MAX_TIME) {
        debug(LOG_ERR, "network can not work well, retried time %d, going to restart system", restart_network);
        restart_system();
    }
#endif

    if (!is_pthreads_welldone()) {
        termination_handler(0);
    }

    if (!last_refresh_time) {
        last_refresh_time = current_time;
    }
    if (current_time - last_refresh_time >= REFRESH_TIME) {
        (void)fw_backup_refresh();
        if (config_get_config()->wd_auth_mode == AUTH_LOCAL_APPCTL) {
            (void)client_record_refresh();
            (void)click_record_refresh();
        }
        last_refresh_time = current_time;
    }
}

void thread_watchdog(char* arg)
{
    struct  timespec        timeout;
    static int run_count;

    pthread_watchdog_init_list();
    while (1) {
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        pthread_mutex_lock(&watchdog_thread_cond_mutex);
        pthread_cond_timedwait(&watchdog_thread_cond, &watchdog_thread_cond_mutex, &timeout);
        pthread_mutex_unlock(&watchdog_thread_cond_mutex);

        cmm_watchdog();
    }
    pthread_watchdog_destory_list();
}

