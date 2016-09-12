/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * test_thread.c
 * Original Author : cjpthree@126.com, 2015-7-10.
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
#include <fcntl.h>
#include <unistd.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "client_access.h"
#include "fw_iptables.h"
#include "util.h"
#include "auth.h"
#include "centralserver.h"
#include "firewall.h"
#include "hlist.h"
#include "fw_iptables.h"
#include "whitelist_thread.h"
#include "client_list.h"
#include "watchdog.h"
#include "fw_backup.h"
#include "click_record_queue.h"
#include "appctl.h"
#include "wifiga_ubus_client.h"
#include "counterfeit.h"

#ifdef debug
#undef debug
#endif
#define debug(level, format, ...) fprintf (stderr, "%s:%s:%d: "format"\n", __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define TEST_TIME       (1000UL)
#define TEST_IPTABLES_DO_COMMAND_TWO_THREAD 1

#ifdef THIS_THREAD_NAME
#undef THIS_THREAD_NAME
#endif
#define THIS_THREAD_NAME    THREAD_TEST_NAME


void client_access_queue_test()
{
    char *mac = "00:00:00:00:22:24";
    char *mac1 = "00:00:00:00:22:25";
    char *mac2 = "00:00:00:00:22:26";
    char *mac3 = "00:00:00:00:22:27";
    char *mac4 = "00:00:00:00:22:28";
    char *mac5 = "00:00:00:00:22:29";
    char buf[MAC_ADDR_LEN];
    int i;

    client_access_queue_init();
    client_access_queue_show_all();

    client_access_queue_enqueue(mac);
    client_access_queue_show_all();

    memset(buf, 0, MAC_ADDR_LEN); // must do memset
    client_access_queue_dequeue(buf);
    debug(LOG_DEBUG, "dequeue enum is %s", buf);
    memset(buf, 0, MAC_ADDR_LEN);
    client_access_queue_dequeue(buf);
    debug(LOG_DEBUG, "dequeue enum is %s", buf);

    client_access_queue_enqueue(mac);
    client_access_queue_enqueue(mac1);
    client_access_queue_enqueue(mac);
    client_access_queue_enqueue(mac2);
    client_access_queue_enqueue(mac3);
    client_access_queue_enqueue(mac4);
    client_access_queue_enqueue(mac5);
    client_access_queue_show_all();

    memset(buf, 0, MAC_ADDR_LEN);
    client_access_queue_peek_last(buf);
    debug(LOG_DEBUG, "peek enum is %s", buf);

    memset(buf, 0, MAC_ADDR_LEN);
    client_access_queue_dequeue(buf);
    debug(LOG_DEBUG, "dequeue enum is %s", buf);

    client_access_queue_show_all();
    client_access_queue_delete(mac3);
    client_access_queue_show_all();

    client_access_queue_destory();
}

void test_get_system_info()
{
    system_info_t info;
    int i;

    for (i = 0; i < 100; i++) {
        memset((void *)&info, 0, sizeof(system_info_t));
        if (get_system_info(&info)) {
            debug(LOG_ERR, "fail to do get_system_info");
        }
        debug(LOG_DEBUG, "version %s, model %s, creation_date %s, SNID %s",
            info.version, info.model, info.creation_date, info.snid);
    }
}

void test_arp_rarp_function()
{
    char *req_ip = "192.168.10.123";
    char *req_mac = "20:f4:1b:80:03:4b";
    char *get_ip;
    char *get_mac;

    get_mac = arp_get(req_ip);
    if (get_mac) {
        debug(LOG_DEBUG, "get mac %s", get_mac);
    }
    careful_free(get_mac);
    get_ip = rarp_get(req_mac);
    if (get_ip) {
        debug(LOG_DEBUG, "get ip %s", get_ip);
    }
    careful_free(get_ip);
}

void test_watchdog()
{
    int i;

    for (i = 0; i < 100; i++) {
        pthread_watchdog_dump_list();
        pthread_watchdog_feed(THIS_THREAD_NAME);
        sleep(120);
    }
}

void test_fw_backup(void)
{
    int i;
        char mac[][MAC_ADDR_LEN] = {
        "ac:bc:ec:23:75:45",
        "ac:bc:ec:23:75:46",
        "ac:bc:ec:23:75:47",
        "AC:BC:EC:23:75:48",
        "AC:BC:EC:23:75:49",
        "AC:BC:EC:23:75:50",
        "AC:A2:13:3B:85:83",
        "00:00:00:00:00:01"};

    client_list_add(mac[0]);
    client_list_add(mac[1]);
    client_list_add(mac[2]);
    sleep(1);
    client_list_add(mac[3]);
    client_list_add(mac[4]);
    client_list_add(mac[6]);
    client_list_set_auth(mac[0], 1);
    client_list_dump();

    for (i = 0; i < 100; i++) {
        fw_backup_from_file();
        sleep(4);
        fw_backup_refresh();
        sleep(4);
    }
}

void test_client_record(void)
{
    int i;
    char mac[][MAC_ADDR_LEN] = {
    "ac:bc:ec:23:75:45",
    "ac:bc:ec:23:75:46",
    "ac:bc:ec:23:75:47",
    "AC:BC:EC:23:75:48",
    "AC:BC:EC:23:75:49",
    "AC:BC:EC:23:75:50",
    "AC:A2:13:3B:85:83",
    "00:00:00:00:00:01"};

    client_record_queue_enqueue(mac[0], time(NULL));
    client_record_queue_enqueue(mac[1], time(NULL));
    client_record_queue_enqueue(mac[2], time(NULL));
    sleep(1);
    client_record_queue_enqueue(mac[3], time(NULL));
    client_record_queue_enqueue(mac[4], time(NULL));
    client_record_queue_enqueue(mac[6], time(NULL));
    client_record_queue_show_all();

    for (i = 0; i < 100; i++) {
        client_record_restore_from_file();
        sleep(2);
        client_record_queue_show_all();
        client_record_refresh();
        sleep(2);
    }
}

void test_click_record_queue(void)
{
    int i;
    click_record_queue_node_t node;
    click_record_queue_node_t item[] = {
        {.appid = "001", .mac = "1c:bc:ec:23:75:45", .type = 1},
        {.appid = "002", .mac = "2c:bc:ec:23:75:45", .type = 0},
        {.appid = "003", .mac = "3c:bc:ec:23:75:45", .type = 2},
        {.appid = "004", .mac = "4c:bc:ec:23:75:45", .type = 1},
        {.appid = "005", .mac = "5c:bc:ec:23:75:45", .type = 0},
        {.appid = "006", .mac = "6c:bc:ec:23:75:45", .type = 1},
    };

    debug(LOG_DEBUG, "");

    for (i = 0; i < sizeof(item) / sizeof(item[0]); i++) {
        click_record_queue_enqueue(item[i].appid, item[i].mac, item[i].type, time(NULL));
    }
    click_record_queue_show_all();

    for (i = 0; i < sizeof(item) / sizeof(item[0]); i++) {
        click_record_queue_dequeue(&node);
        debug(LOG_DEBUG, "appid %s, mac %s, type %d, time %d", node.appid, node.mac, node.type, node.click_time);
    }
    click_record_queue_show_all();
}

void test_click_record_backup(void)
{
    int i;
    click_record_queue_node_t node;
    click_record_queue_node_t item[] = {
        {.appid = "001", .mac = "1c:bc:ec:23:75:45", .type = 1},
        {.appid = "002", .mac = "2c:bc:ec:23:75:45", .type = 0},
        {.appid = "003", .mac = "3c:bc:ec:23:75:45", .type = 2},
        {.appid = "004", .mac = "4c:bc:ec:23:75:45", .type = 1},
        {.appid = "005", .mac = "5c:bc:ec:23:75:45", .type = 0},
        {.appid = "006", .mac = "6c:bc:ec:23:75:45", .type = 1},
    };

    debug(LOG_DEBUG, "");

    for (i = 0; i < sizeof(item) / sizeof(item[0]); i++) {
        click_record_queue_enqueue(item[i].appid, item[i].mac, item[i].type, time(NULL));
    }
    for (i = 0; i < 100; i++) {
        click_record_restore_from_file();
        sleep(2);
        click_record_queue_show_all();
        click_record_refresh();
        sleep(2);
    }
}



static pthread_t tid_iptables_do_command = 0;
static pthread_t tid_iptables_do_command1 = 0;

static int
iptables_fw_access_mac_only(fw_access_t type, char *mac)
{
	int rc = 0;

	switch(type) {
		case FW_ACCESS_ALLOW:
			iptables_do_command("-t mangle -A " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark 2", mac);
			break;
		case FW_ACCESS_DENY:
			iptables_do_command("-t mangle -D " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark 2", mac);
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}

static pthread_mutex_t fw_tracked_mac_mutex = PTHREAD_MUTEX_INITIALIZER;
void test_iptables_do_command(char* arg)
{
    int i;
    char mac[MAC_ADDR_LEN] = "40:a5:ef:0b:1f:cb";
    (void)client_list_add(mac);

    for (i = 0; i < TEST_TIME; i++) {
        debug(LOG_DEBUG, ".testing. %d time", i);
        iptables_fw_access_mac_only(FW_ACCESS_ALLOW, mac);
        //(void)iptables_fw_tracked_mac(mac);
        usleep(100);
    }
}

void test_iptables_do_command1(char* arg)
{
    int i;
    char mac[MAC_ADDR_LEN] = "40:a5:ef:0b:1f:cb";

    usleep(100);

    for (i = 0; i < TEST_TIME; i++) {
        debug(LOG_DEBUG, ".testing1. %d time", i);
        iptables_fw_access_mac_only(FW_ACCESS_ALLOW, mac);
        //(void)iptables_fw_untracked_mac(mac);
        usleep(100);
    }
}

void testcurl(void)
{
   char * date = NULL;
	char URL[256] = {0};
	int i,j;
	int ret;

	sprintf(URL, "http://www.baidu.com");
	debug(LOG_ERR,"http get is %s", URL);
	date = curl_http_get(URL,HTTP_TIMEOUT);
	if (date != NULL) {
	    debug(LOG_ERR,"http response is %s", date );
	} else {
        debug(LOG_ERR,"can not get anything");
	    return;
	}
	careful_free(date);

	ret = curl_http_get2(URL,HTTP_TIMEOUT,"/tmp/curlfile");
	if (ret == 0) {
	    debug(LOG_ERR,"down file ok");
	} else {
        debug(LOG_ERR,"can not down file");
	    return;
	}

	sprintf(URL, "http://%s:%s/", "www.baidu.com", "80");
    debug(LOG_ERR,"http post is %s", URL);
    date = curl_http_post(URL, NULL, "hello", HTTP_TIMEOUT);
    careful_free(date);
}


void test_onoffline_enqueue()
{
    while (1) {
        onoffline_enqueue("00:22:44:66:88:aa", 1, "3", time(NULL));
        onoffline_enqueue("11:22:44:66:88:aa", 1, "3", time(NULL));
        onoffline_enqueue("22:22:44:66:88:aa", 1, "3", time(NULL));
        onoffline_enqueue("33:22:44:66:88:aa", 1, "3", time(NULL));
        onoffline_enqueue("00:22:44:66:88:bb", 0, "3", time(NULL));
        sleep(2);
        onoffline_enqueue("11:22:44:66:88:bb", 0, "3", time(NULL));
    }
}

void test_dumy_phone()
{
    char phone[PHONE_NUMBER_LEN] = {0};
    printf("----------phone %s\n", phone);sleep(1);
    (void)counterfeit_phone_num(phone);
    printf("----------phone %s\n", phone);sleep(1);
}

void thread_test(char* arg)
{
    int result;
    int i;

    debug(LOG_DEBUG, "testing thread");

#if 0
	result = pthread_create(&tid_iptables_do_command, NULL, (void*)test_iptables_do_command, NULL);
	if (result != 0) {
		debug(LOG_ERR,"FATAL: Failed to create a new thread(for test iptables_do_command) -exiting");
		termination_handler(0);
	}
	pthread_detach(tid_iptables_do_command);

#if TEST_IPTABLES_DO_COMMAND_TWO_THREAD
    result = pthread_create(&tid_iptables_do_command1, NULL, (void*)test_iptables_do_command1, NULL);
	if (result != 0) {
		debug(LOG_ERR,"FATAL: Failed to create a new thread(for test iptables_do_command1) -exiting");
		termination_handler(0);
	}
	pthread_detach(tid_iptables_do_command1);
#endif
#endif

#if 0

    client_access_queue_test();

    mac_white_list_test();
    mac_iptables_list_test();
    mac_iptables_list_test_iterator();
    Test_syncOpen();
    TestWhitelist_func();
    test_white_list();
    test_clientlist_func();

    TestWhitelist_func();
    //test_white_list();
#endif /*0 */

#if 0
    mac_iptables_list_test_iterator();

    test_clientlist_func();

    test_get_system_info();

    test_arp_rarp_function();

    pthread_watchdog_register(THREAD_WHITE_LIST_NAME);
    test_watchdog();

    test_fw_backup();

    client_list_test();


    testcurl();
    test_client_record();
    //test_click_record_queue();
    test_click_record_backup();
    appctl_test();
    test_onoffline_enqueue();

    test_auto_conn();
#endif /*0 */
    test_dumy_phone();


}

