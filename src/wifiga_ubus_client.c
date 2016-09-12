/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * wifiga_ubus_client.c
 * Original Author : chenjunpei@jarxi.com, 2016-9-5.
 *
 * Description
 * CCC: this file is not thread safety, add lock when using in multithreading
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>

#include <libubox/ustream.h>

#include "libubus.h"

#include "common.h"
#include "debug.h"
#include "conf.h"
#include "safe.h"
#include "link_queue.h"
#include "client_list.h"


#define _ENABLE_MIAN_ 0

#define MAX_RSSI_LEN    (128UL)
typedef struct onoffline_s {
    char mac[MAC_ADDR_LEN];
    char rssi[MAX_RSSI_LEN];
    int is_online;
    time_t time;
} onoffline_t;


static struct ubus_context *ctx;
static struct blob_buf b;

static link_queue_t online_queue = link_queue_init(online_queue);
static link_queue_t offline_queue = link_queue_init(offline_queue);


int onoffline_enqueue(char *mac, int isonline, char *rssi, time_t time)
{
	link_queue_node_t *pt = NULL;
	onoffline_t new_data;

    memset(&new_data, 0, sizeof(new_data));
	memcpy(new_data.mac, mac, strlen(mac));
    memcpy(new_data.rssi, rssi, strlen(rssi));
    new_data.is_online = isonline;
    new_data.time = time;

	link_queue_create_node(pt, &new_data, sizeof(new_data));
    if (!pt) {
		printf("link queue create fail\n");
		return -1;
	}
    if (isonline) {
	    link_queue_enqueue(&online_queue, pt);
    } else {
        link_queue_enqueue(&offline_queue, pt);
    }

	return 0;
}


static void wifiga_client_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
	fprintf(stderr, "Subscribers active: %d\n", obj->has_subscribers);
}

static struct ubus_object wifiga_client_object = {
	.subscribe_cb = wifiga_client_subscribe_cb,
};

enum {
	RETURN_CODE,
	__RETURN_MAX,
};

static const struct blobmsg_policy return_policy[__RETURN_MAX] = {
	[RETURN_CODE] = { .name = "rc", .type = BLOBMSG_TYPE_INT32 },
};

static void handle_online_data_cb(struct ubus_request *req,
				    int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__RETURN_MAX];
	int rc;
	char *mac = (char *)req->priv;

	blobmsg_parse(return_policy, __RETURN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RETURN_CODE]) {
		fprintf(stderr, "No return code received from server\n");
		return;
	}
	rc = blobmsg_get_u32(tb[RETURN_CODE]);
	if (rc) {
		fprintf(stderr, "Corruption of data with online up to %s\n", mac);
	} else {
		fprintf(stderr, "Server validated our online up to %s\n", mac);
	}
}

static void handle_online(struct uloop_timeout *timeout)
{
	uint32_t id;
    link_queue_node_t *pt = NULL;
    onoffline_t *data = NULL;

	if (ubus_lookup_id(ctx, "wifiga", &id)) {
		fprintf(stderr, "Failed to look up wifiga object\n");
		return;
	}

    while (!link_queue_is_empty(&online_queue)) {
        link_queue_dequeue(&online_queue, pt);
        if (!pt) {
            continue;
        }
        data = link_queue_parse_data(pt, onoffline_t);
        if (data) {
            blob_buf_init(&b, 0);
            blobmsg_add_string(&b, "mac", data->mac);
        	blobmsg_add_string(&b, "rssi", data->rssi);
        	blobmsg_add_u64(&b, "time", data->time);
        	ubus_invoke(ctx, id, "online", b.head, handle_online_data_cb, data->mac, 5000);
        }
        link_queue_free_node(pt);
    }
    uloop_timeout_set(timeout, 1000);
}

static struct uloop_timeout online_timer = {
	.cb = handle_online,
};

static void handle_offline_data_cb(struct ubus_request *req,
				    int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__RETURN_MAX];
	int rc;
	char *mac = (char *)req->priv;

	blobmsg_parse(return_policy, __RETURN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RETURN_CODE]) {
		fprintf(stderr, "No return code received from server\n");
		return;
	}
	rc = blobmsg_get_u32(tb[RETURN_CODE]);
	if (rc) {
		fprintf(stderr, "Corruption of data with offline up to %s\n", mac);
	} else {
		fprintf(stderr, "Server validated our offline up to %s\n", mac);
	}
}

static void handle_offline(struct uloop_timeout *timeout)
{
	uint32_t id;
	link_queue_node_t *pt = NULL;
    onoffline_t *data = NULL;

	if (ubus_lookup_id(ctx, "wifiga", &id)) {
		fprintf(stderr, "Failed to look up wifiga object\n");
		return;
	}

    while (!link_queue_is_empty(&offline_queue)) {
        link_queue_dequeue(&offline_queue, pt);
        if (!pt) {
            continue;
        }
        data = link_queue_parse_data(pt, onoffline_t);
        if (data) {
            blob_buf_init(&b, 0);
            blobmsg_add_string(&b, "mac", data->mac);
        	blobmsg_add_string(&b, "rssi", data->rssi);
        	blobmsg_add_u64(&b, "time", data->time);
	        ubus_invoke(ctx, id, "offline", b.head, handle_offline_data_cb, data->mac, 5000);
        }
        link_queue_free_node(pt);
    }
    uloop_timeout_set(timeout, 2000);
}

static struct uloop_timeout offline_timer = {
	.cb = handle_offline,
};

static void wifiga_ubus_client_run(void)
{
	static struct ubus_request req;
	uint32_t id;
	int ret;

	ret = ubus_add_object(ctx, &wifiga_client_object);
	if (ret) {
		fprintf(stderr, "Failed to add_object object: %s\n", ubus_strerror(ret));
		return;
	}

	if (ubus_lookup_id(ctx, "wifiga", &id)) {
		fprintf(stderr, "Failed to look up wifiga object\n");
		return;
	}

	uloop_timeout_set(&online_timer, 1000);
    uloop_timeout_set(&offline_timer, 2000);

	uloop_run();
}

int wifiga_ubus_client_main_loop(void *ubus_socket)
{
	uloop_init();

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	ubus_add_uloop(ctx);

	wifiga_ubus_client_run();

	ubus_free(ctx);
	uloop_done();

	return 0;
}

void wifiga_ubus_client_exit(void)
{
    ubus_free(ctx);
	uloop_done();
}


/******************** ubus_auto_conn *****************************/

static struct ubus_context *ubus_ctx = NULL;
static struct ubus_auto_conn conn;

static void ubus_connect_handler(struct ubus_context *ctx)
{
    ubus_ctx = ctx;
    return;
}

int ubus_send(const char *type, struct blob_attr *data)
{
    if (!ubus_ctx || !type || !data) {
        return -1;
    }
    return ubus_send_event(ubus_ctx, type, data);
}

static void receive_ubus_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *ret = (char *)req->priv;
}

int ubus_call(const char *path, const char *method, struct blob_attr *data, void *ret)
{
    uint32_t id;
    int      _ret;

    if (ubus_ctx == NULL) {
        debug(LOG_ERR, "ubus_ctx == NULL!");
        return -1;
    }

    _ret = ubus_lookup_id(ubus_ctx, path, &id);
    if (_ret) {
        debug(LOG_ERR, "lookup stats id error!");
        return -1;
    }

    return ubus_invoke(ubus_ctx, id, method, data, receive_ubus_data, ret, 1000);
}

int ubus_init(void)
{
    conn.cb = ubus_connect_handler;
    ubus_auto_connect(&conn);

    return 0;
}

void ubus_destory()
{
   //ubus_free(ubus_ctx); // would make a Segmentation fault, did not need to do free
}

int report_onoffline(const char *mac)
{
    client_t client;
    config_t *config = config_get_config();
    int ret = -1;

    memset(&client, 0, sizeof(client_t));
    if (client_list_get_client(mac, &client)) {
        debug(LOG_ERR, "get client error!");
        return -1;
    }
    debug(LOG_DEBUG, "mac %s, ip %s, rssi %d, account %s", mac, client.ip, client.rssi, client.account);

	blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "mac", mac);
    blobmsg_add_string(&b, "ip", client.ip);
    blobmsg_add_string(&b, "extip", config->extip);
	blobmsg_add_u32(&b, "rssi", client.rssi); /* CCC: int elem cannot be 0 */
    blobmsg_add_u32(&b, "authmode", config->wd_auth_mode);
    blobmsg_add_string(&b, "account", client.account);
	blobmsg_add_u64(&b, "time", time(NULL));

    if (CLIENT_ONLINE == client.onoffline) {
        ret = ubus_call("wifiga", "online", b.head, (void *)mac);
    } else {
        ret = ubus_call("wifiga", "offline", b.head, (void *)mac);
    }
    (void)client_list_set_reported(mac, CLIENT_STATUS_REPORTED);

    return ret;
}

void test_auto_conn(void)
{
    time_t curr_time = time(NULL);
    int i;
    char mac[MAC_ADDR_LEN] = "00:00:00:00:00:01";

    client_list_add(mac);
    client_list_set_ip(mac, "192.168.99.2");
    client_list_set_account(mac, "account_test");
    client_list_set_rssi(mac, -23);

    //ubus_init();
    for (i = 0; i < 1; i++) {
        report_onoffline(mac);
        sleep(3);
    }
    //ubus_destory();
}

#if _ENABLE_MIAN_
int main(int argc, char **argv)
{
	const char *ubus_socket = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "cs:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		default:
			break;
		}
	}

	argc -= optind;
	argv += optind;

    wifiga_ubus_client_main_loop(ubus_socket);

    return 0;
}
#endif

