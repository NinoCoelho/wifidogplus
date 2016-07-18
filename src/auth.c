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
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "watchdog.h"

#ifdef THIS_THREAD_NAME
#undef THIS_THREAD_NAME
#endif
#define THIS_THREAD_NAME    THREAD_FW_COUNTER_NAME


/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress?
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_client_timeout_check(const void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;

	while (1) {
		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);

		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);

		debug(LOG_DEBUG, "Running fw_counter()");

        pthread_watchdog_feed(THIS_THREAD_NAME);
		fw_sync_with_authserver();
        pthread_watchdog_feed(THIS_THREAD_NAME);
	}
}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
*/
void
authenticate_client(char *mac, request *r)
{
	t_authresponse	auth_response;
	char *urlFragment = NULL;
	s_config	*config = NULL;
	t_auth_serv	*auth_server = NULL;
    client_t        client;
    int    auth;

#if _CHECK_CAREFUL_
    if (!is_mac_valid(mac) || !r || !client_list_is_exist(mac)) {
        return;
    }
#endif

	/* Prepare some variables we'll need below */
	config = config_get_config();
	auth_server = get_auth_server();

    memset((void *)&client, 0, sizeof(client_t));
    if (!client_list_get_client(mac, &client)) {
        if (client.auth > CLIENT_CHAOS) {
            debug(LOG_DEBUG, "mac %s had authenticated", mac);
            (void)iptables_fw_allow_mac(mac);
            (void)client_list_set_last_updated(mac, time(NULL));
            safe_asprintf(&urlFragment, "%sdev_name=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&gw_id=%s&gw_address=%s&gw_port=%d",
    			auth_server->authserv_portal_script_path_fragment,
                client.hostname,
		        client.ip,
		        client.mac,
		        client.token,
		        client.counters.incoming,
		        client.counters.outgoing,
                config_get_config()->gw_id,
                config_get_config()->gw_address,
                config_get_config()->gw_port
    		);
    		http_send_redirect_to_auth(r, urlFragment, "Redirect to portal");
    		careful_free(urlFragment);
            return;
        }
    } else {
        debug(LOG_ERR, "mac %s fail to get client info", mac);
        (void)client_list_add(mac);
        (void)client_list_set_ip(mac, r->clientAddr);
        (void)iptables_fw_tracked_mac(mac);
        memset((void *)&client, 0, sizeof(client_t));
        (void)client_list_get_client(mac, &client);
    }
    (void)client_list_set_last_updated(mac, time(NULL));

	/*
	 * At this point we've released the lock while we do an HTTP request since it could
	 * take multiple seconds to do and the gateway would effectively be frozen if we
	 * kept the lock.
	 */
	auth_server_request(&auth_response, REQUEST_TYPE_LOGIN,
	    client.ip, client.mac, client.token, 0, 0);

	switch(auth_response.authcode) {
	case AUTH_ERROR:
		/* Error talking to central server */
		debug(LOG_ERR, "Got %d from central server authenticating token %s from %s at %s",
		auth_response, client.token, client.ip, client.mac);
		send_http_page(r, "Error!", "Error: We did not get a valid answer from the central server");
		break;

	case AUTH_DENIED:
		/* Central server said invalid token */
		debug(LOG_INFO, "Got DENIED from central server authenticating token %s from %s at %s - deleting from firewall and redirecting them to denied message",
		client.token, client.ip, client.mac);
        /* fixbug: get whitelist_mac when asking auth server */
        if (client_list_get_auth(mac, &auth)) {
            auth = CLIENT_UNAUTH;
        }
        if (auth >= CLIENT_CONFIG) {
            debug(LOG_DEBUG, "mac %s is in config, can not delete", mac);
            safe_asprintf(&urlFragment, "%sdev_name=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&gw_id=%s&gw_address=%s&gw_port=%d",
    			auth_server->authserv_portal_script_path_fragment,
                client.hostname,
		        client.ip,
		        client.mac,
		        client.token,
		        client.counters.incoming,
		        client.counters.outgoing,
                config_get_config()->gw_id,
                config_get_config()->gw_address,
                config_get_config()->gw_port
    		);
    		http_send_redirect_to_auth(r, urlFragment, "Redirect to portal");
    		careful_free(urlFragment);
            break;
        }

        (void)client_list_set_auth(mac, CLIENT_UNAUTH);
        (void)iptables_fw_deny_mac(mac);
		/*safe_asprintf(&urlFragment, "%smessage=%s",
			auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_DENIED
		);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to denied message");*/
        extern httpd * webserver;
        http_callback_404(webserver, r);
		careful_free(urlFragment);
		break;

    case AUTH_ALLOWED:
		/* Logged in successfully as a regular account */
		debug(LOG_INFO, "Got ALLOWED from central server authenticating token %s from %s at %s - "
				"adding to firewall and redirecting them to portal", client.token, client.ip, client.mac);
        (void)client_list_set_auth(mac, CLIENT_COMMON);
        (void)iptables_fw_allow_mac(mac);
		safe_asprintf(&urlFragment, "%sdev_name=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&gw_id=%s&gw_address=%s&gw_port=%d",
			auth_server->authserv_portal_script_path_fragment,
            client.hostname,
	        client.ip,
	        client.mac,
	        client.token,
	        client.counters.incoming,
	        client.counters.outgoing,
            config_get_config()->gw_id,
            config_get_config()->gw_address,
            config_get_config()->gw_port
		);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to portal");
		careful_free(urlFragment);
	    break;

    case AUTH_VIP:
		(void)client_list_set_auth(mac, CLIENT_VIP);
        (void)iptables_fw_allow_mac(mac);
		safe_asprintf(&urlFragment, "%sdev_name=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&gw_id=%s&gw_address=%s&gw_port=%d",
			auth_server->authserv_portal_script_path_fragment,
            client.hostname,
	        client.ip,
	        client.mac,
	        client.token,
	        client.counters.incoming,
	        client.counters.outgoing,
            config_get_config()->gw_id,
            config_get_config()->gw_address,
            config_get_config()->gw_port
		);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to portal");
		careful_free(urlFragment);
		break;

    case AUTH_VALIDATION_FAILED:
		 /* Client had X minutes to validate account by email and didn't = too late */
		debug(LOG_INFO, "Got VALIDATION_FAILED from central server authenticating token %s from %s at %s "
				"- redirecting them to failed_validation message", client.token, client.ip, client.mac);
		safe_asprintf(&urlFragment, "%smessage=%s",
			auth_server->authserv_msg_script_path_fragment,
			GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED
		);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to failed validation message");
		careful_free(urlFragment);
	    break;

    default:
		debug(LOG_WARNING, "I don't know what the validation code %d means for token %s from %s at %s - sending error message",
            auth_response.authcode, client.token, client.ip, client.mac);
		send_http_page(r, "Internal Error", "We can not validate your request at this time");
	    break;
	}

    debug(LOG_INFO, "the client %s (%s) auth %u fw_state",
        client.ip, client.mac, client.auth, client.fw_state);

	return;
}


