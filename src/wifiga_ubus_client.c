/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * wifiga_ubus_client.c
 * Original Author : chenjunpei@jarxi.com, 2016-9-5.
 *
 * Description
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


#define _ENABLE_MIAN_ 0


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

	link_queue_alloc_node(pt, sizeof(onoffline_t));
	if (!pt) {
		printf("alloc fail\n");
		return -1;
	}

    memset(&new_data, 0, sizeof(new_data));
	memcpy(new_data.mac, mac, strlen(mac));
    memcpy(new_data.rssi, rssi, strlen(rssi));
    new_data.is_online = isonline;
    new_data.time = time;

	link_queue_init_node(pt, &new_data, sizeof(new_data));
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

