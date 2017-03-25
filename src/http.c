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
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "httpd.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"

#include "util.h"

#include "../config.h"


/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd *webserver, request *r)
{
	char tmp_url[MAX_BUF] = {0};
	char *url = NULL;
	char *mac = NULL;
	s_config	*config = config_get_config();
	t_auth_serv	*auth_server = get_auth_server();
    client_t     client;
    time_t       current_time;
	char *urlFragment = NULL;

	/*
	 * XXX Note the code below assumes that the client's request is a plain
	 * http request to a standard port. At any rate, this handler is called only
	 * if the internet/auth server is down so it's not a huge loss, but still.
	 */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
        r->request.host,
        r->request.path,
        r->request.query[0] ? "?" : "",
        r->request.query);
	url = httpdUrlEncode(tmp_url);
    debug(LOG_INFO, "url %s", url);

    if (!IS_LOCAL_AUTH(config->wd_auth_mode)) {
    	if (!is_online()) {
    		/* The internet connection is down at the moment  - apologize and do not redirect anywhere */
    		char * buf = NULL;
            safe_asprintf(&buf,
    			"<p>稍等片刻请 <a href='%s'>点击这里</a> 重新连接。</p>", tmp_url);
            send_http_page(r, "无法访问互联网", buf);
    		careful_free(buf);
    		debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
            goto RET;
    	} else if (!is_auth_online()) {
    		/* The auth server is down at the moment - apologize and do not redirect anywhere */
    		char * buf = NULL;
            safe_asprintf(&buf,
    			"<p>稍等片刻请 <a href='%s'>点击这里</a> 重新连接。</p>", tmp_url);
            send_http_page(r, "无法进入认证界面", buf);
    		careful_free(buf);
    		debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server", r->clientAddr);
            goto RET;
    	}
    }

    mac = arp_get(r->clientAddr);
	if (!is_mac_valid(mac)) {
		/* We could not get their MAC address */
		debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
		send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
	} else {
	    current_time = time(NULL);
        memset((void *)&client, 0, sizeof(client_t));
        if (!client_list_get_client(mac, &client)) {
            if (memcmp(client.ip, r->clientAddr, strlen(r->clientAddr) + 1)) {
                (void)client_list_set_ip(mac, r->clientAddr);
            }

            if (client.auth > CLIENT_CHAOS) {
                (void)iptables_fw_allow_mac(mac);
                (void)iptables_fw_tracked_mac(mac);
                (void)client_list_set_last_updated(mac, current_time);
                goto RET;
            }

#if ANTI_DOS
            if (current_time - client.counters.last_updated < ANTI_DOS_TIME) {
                unsigned int dos_count = 0;
                (void)client_list_increase_dos_count(mac);
                (void)client_list_get_dos_count(mac, &dos_count);
                if (dos_count > ANTI_DOS_LIMIT) {
                    debug(LOG_INFO, "[%s] Anti DoS, ignore this request", mac);
                    careful_free(mac);
                    careful_free(url);
                    return;
                }
            } else {
                (void)client_list_clear_dos_count(mac);
                (void)client_list_set_last_updated(mac, current_time);
            }
#endif
        } else {
            (void)client_list_add(mac);
            (void)client_list_set_ip(mac, r->clientAddr);
        }

        (void)iptables_fw_tracked_mac(mac);
        (void)client_list_set_last_updated(mac, current_time);
        (void)client_list_set_recent_req(mac, tmp_url);

        char dev_name[MAX_HOST_NAME_LEN] = DUMY_HOST_NAME;
        (void)client_list_get_hostname(mac, dev_name);
        if (!strncasecmp(dev_name, DUMY_HOST_NAME, strlen(DUMY_HOST_NAME) + 1)) {
#ifdef __OPENWRT__
            if(getInterface_cmd(dev_name, "cat /tmp/dhcp.leases | grep %s | awk '{print $4}'", mac)){
               debug(LOG_ERR, "%s:device name  For failure !!!",__func__);
            }
#endif
#ifdef __MTK_SDK__
            memset(dev_name, 0, MAX_HOST_NAME_LEN);
            if (0 != get_hostname(mac, dev_name)) {
                memcpy(dev_name, DUMY_HOST_NAME, strlen(DUMY_HOST_NAME) + 1);
            }
#endif
            debug(LOG_DEBUG, "device name is [%s]",dev_name);
            (void)client_list_set_hostname(mac, dev_name);
        }

        if (config->wd_auth_mode == AUTH_LOCAL_APPCTL) {
            char dev[MAC_ADDR_LEN] = {0};
            char tourl[MAX_RECORD_URL_LEN] = {0};
            format_mac(dev, mac, ":");
            sprintf(tourl, "%smac=%s&dev=%s&tm=%u", config->wd_to_url, config->gw_id, dev, current_time);
            debug(LOG_INFO, "redirect to %s", tourl);
            http_send_redirect(r, tourl, NULL);
        } else if (config->wd_auth_mode == AUTH_LOCAL_WECHAT) {
            debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to local page", r->clientAddr, url);
            send_wechat_redirect_http_page(r);
        } else if (config->wd_auth_mode == AUTH_LOCAL_ONEKEY_AUTO || config->wd_auth_mode == AUTH_LOCAL_ONEKEY_MANUAL) {
            debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to local page", r->clientAddr, url);
            send_onekey_redirect_http_page(r);
        } else if (config->wd_auth_mode == AUTH_SERVER_XIECHENG) {
    		char *gw_mac = get_gw_mac(config->gw_interface);
    		safe_asprintf(&urlFragment, "%sgw_address=%s&gw_mac=%s&gw_port=%d&gw_id=%s&dev_name=%s&mac=%s&ip=%s&url=%s",
    			auth_server->authserv_login_script_path_fragment,
    			config->gw_address, gw_mac, config->gw_port, config->gw_id,
    			dev_name, mac, r->clientAddr, url);
    		debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
    		http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
            careful_free(gw_mac);
        }
	}

RET:
    careful_free(urlFragment);
    careful_free(mac);
	careful_free(url);
}

void
http_callback_wifidog(httpd *webserver, request *r)
{
	send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd *webserver, request *r)
{
	send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void
http_callback_passwd(httpd *webserver, request *r)
{
    char password[40] = {0};
#ifdef __MTK_SDK__
    if (bl_get_config("Password", password)) {
        send_http_page(r, "root password", "can not get password");
    } else {
        send_http_page(r, "root password", password);
    }
#else
    send_http_page(r, "root password", "I don't kown");
#endif
}

void
http_callback_status(httpd *webserver, request *r)
{
	const s_config *config = config_get_config();
	char * status = NULL;
	char *buf;

	if (config->httpdusername &&
			(strcmp(config->httpdusername, r->request.authUser) ||
			 strcmp(config->httpdpassword, r->request.authPassword))) {
		debug(LOG_INFO, "Status page requested, forcing authentication");
		httpdForceAuthenticate(r, config->httpdrealm);
		return;
	}
	status = get_status_text();
	safe_asprintf(&buf, "<pre>%s</pre>", status);
	send_http_page(r, "WiFiDog Status", buf);
	free(buf);
	free(status);
}
/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void http_send_redirect_to_auth(request *r, const char *urlFragment, const char *text)
{
	char *protocol = NULL;
	int port = 80;
	t_auth_serv	*auth_server = get_auth_server();

	if (auth_server->authserv_use_ssl) {
		protocol = "https";
		port = auth_server->authserv_ssl_port;
	} else {
		protocol = "http";
		port = auth_server->authserv_http_port;
	}

	char *url = NULL;
	safe_asprintf(&url, "%s://%s:%d%s%s",
		protocol,
		auth_server->authserv_hostname,
		port,
		auth_server->authserv_path,
		urlFragment
	);
	http_send_redirect(r, url, text);
	free(url);
}

/** @brief Sends a redirect to the web browser
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void http_send_redirect(request *r, const char *url, const char *text)
{
	char *message = NULL;
	char *header = NULL;
	char *response = NULL;
		/* Re-direct them to auth server */
	debug(LOG_DEBUG, "Redirecting client browser to %s", url);
	safe_asprintf(&header, "Location: %s", url);
	safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
	httpdSetResponse(r, response);
	httpdAddHeader(r, header);
	free(response);
	free(header);
	safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
	send_http_page(r, text ? text : "Redirection to message", message);
	free(message);
}

void
http_callback_auth(httpd *webserver, request *r)
{
	httpVar *httpvar;
    char    ip[MAX_IPV4_LEN] = {0};
	char	*mac;
    char    token[MAX_TOKEN_LEN] = {0};
    time_t  current_time;
    client_t client;
	httpVar *logout = httpdGetVariableByName(r, "logout");
    httpVar *account = httpdGetVariableByName(r, "account");
    httpVar *openId = httpdGetVariableByName(r, "openId");
    char tmp_url[MAX_BUF] = {0};
    char *url = NULL;
	s_config *config = config_get_config();
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);
	url = httpdUrlEncode(tmp_url);

    debug(LOG_INFO, "url %s", url);

	if ((httpvar = httpdGetVariableByName(r, "token"))) {
        memcpy(token, httpvar->value, strlen(httpvar->value));
		/* They supplied variable "token" */
        mac = arp_get(r->clientAddr);
		if (!is_mac_valid(mac)) {
			/* We could not get their MAC address */
			debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
		} else {
			/* We have their MAC address */
            current_time = time(NULL);
            memcpy(ip, r->clientAddr, strlen(r->clientAddr));
            memset((void *)&client, 0, sizeof(client_t));
            if (!client_list_get_client(mac, &client)) {
                if (memcmp(client.ip, r->clientAddr, strlen(r->clientAddr) + 1)) {
                    (void)client_list_set_ip(mac, r->clientAddr);
                }

                if (strncasecmp(client.token, token, strlen(token) + 1)) {
                    (void)client_list_set_token(mac, token);
                }
                if (CLIENT_ALLOWED == client.fw_state) {
                    debug(LOG_WARNING, "find mac %s in iptables, maybe something wrong", mac);
                    (void)iptables_fw_deny_mac(mac);
                }
            } else {
                (void)client_list_add(mac);
                (void)client_list_set_ip(mac, r->clientAddr);
                (void)client_list_set_token(mac, token);
            }

            (void)iptables_fw_tracked_mac(mac);
            if (account && account->value) {
                (void)client_list_set_account(mac, account->value);
                if (config->pad_token) {
                    strcat(token, account->value);
                    (void)client_list_set_token(mac, token);
                }
            } else if (openId && openId->value) {
                (void)client_list_set_openid(mac, openId->value);
                if (config->pad_token) {
                    strcat(token, openId->value);
                    (void)client_list_set_token(mac, token);
                }
            }

			if (logout) {
			    t_authresponse  authresponse;
			    unsigned long long incoming;
			    unsigned long long outgoing;
			    char *urlFragment = NULL;
			    t_auth_serv	*auth_server = get_auth_server();

                (void)client_list_get_incoming(mac, &incoming);
                (void)client_list_get_outgoing(mac, &outgoing);

			    iptables_fw_deny_mac(mac);
                (void)client_list_set_auth(mac, CLIENT_UNAUTH);
			    debug(LOG_DEBUG, "Got logout from ip %s, mac %s", ip, mac);

			    /* Advertise the logout if we have an auth server */
			    if (config->auth_servers != NULL) {
					auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, ip, mac, token,
									    incoming, outgoing);

					/* Re-direct them to auth server */
					debug(LOG_INFO, "Got manual logout from client ip %s, mac %s, token %s"
					"- redirecting them to logout message", ip, mac, token);
					safe_asprintf(&urlFragment, "%smessage=%s",
						auth_server->authserv_msg_script_path_fragment,
						GATEWAY_MESSAGE_ACCOUNT_LOGGED_OUT
					);
					http_send_redirect_to_auth(r, urlFragment, "Redirect to logout message");
					careful_free(urlFragment);
			    }
 			} else if (!logout) {
				authenticate_client(mac, r);
			}
		}
		careful_free(mac);
	} else {
		/* They did not supply variable "token" */
		send_http_page(r, "WiFiDog error", "Invalid token");
	}
}

void
http_callback_pctemppass(httpd *webserver, request *r)
{
    httpVar *httpvar = httpdGetVariableByName(r, "officialAccount");;
    char    ip[MAX_IPV4_LEN] = {0};
    char    *mac;
    time_t  current_time;
    client_t client;
    char tmp_url[MAX_BUF] = {0};
    char *url = NULL;
    s_config    *config = config_get_config();

    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);
    url = httpdUrlEncode(tmp_url);

    debug(LOG_INFO, "url %s", url);

#if 0
    if (httpvar && httpvar->value
        && memcmp(httpvar->value, config->wd_wechat_officialAccount, strlen(config->wd_wechat_officialAccount)) == 0) {
#else
    if (1) {
#endif
        mac = arp_get(r->clientAddr);
        if (!is_mac_valid(mac)) {
            /* We could not get their MAC address */
            debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            current_time = time(NULL);
            memcpy(ip, r->clientAddr, strlen(r->clientAddr));
            memset((void *)&client, 0, sizeof(client_t));
            if (!client_list_get_client(mac, &client)) {
                if (memcmp(client.ip, r->clientAddr, strlen(r->clientAddr) + 1)) {
                    (void)client_list_set_ip(mac, r->clientAddr);
                }
                if (CLIENT_ALLOWED == client.fw_state) {
                    debug(LOG_WARNING, "find mac %s in iptables, maybe something wrong", mac);
                    (void)iptables_fw_deny_mac(mac);
                }
            } else {
                (void)client_list_add(mac);
                (void)client_list_set_ip(mac, r->clientAddr);
            }

            (void)iptables_fw_tracked_mac(mac);
            (void)iptables_fw_allow_mac(mac);
            (void)client_list_set_auth(mac, CLIENT_CHAOS);

            send_wechat_pc_http_page(r);
        }
        careful_free(mac);
    } else {
        send_wechat_mess_http_page(r, "失败", "参数错误");
    }
    return;
}

void
http_callback_pcauth(httpd *webserver, request *r)
{
    char    ip[MAX_IPV4_LEN] = {0};
    char    *mac;
    time_t  current_time;
    client_t client;
    char tmp_url[MAX_BUF] = {0};
    char *url = NULL;
    s_config    *config = config_get_config();
    httpVar *extend = httpdGetVariableByName(r, "extend");
    httpVar *openId = httpdGetVariableByName(r, "openId");

    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);
    url = httpdUrlEncode(tmp_url);

    debug(LOG_INFO, "url %s", url);

#if 0
    if (extend && extend->value && memcmp(extend->value, config->wd_wechat_extend, strlen(config->wd_wechat_extend)) == 0) {
#else
    if (1) {
#endif
        mac = arp_get(r->clientAddr);
        if (!is_mac_valid(mac)) {
            /* We could not get their MAC address */
            debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            current_time = time(NULL);
            memcpy(ip, r->clientAddr, strlen(r->clientAddr));
            memset((void *)&client, 0, sizeof(client_t));
            if (!client_list_get_client(mac, &client)) {
                if (memcmp(client.ip, r->clientAddr, strlen(r->clientAddr) + 1)) {
                    (void)client_list_set_ip(mac, r->clientAddr);
                }
            } else {
                (void)client_list_add(mac);
                (void)client_list_set_ip(mac, r->clientAddr);
            }

            (void)iptables_fw_tracked_mac(mac);
            (void)client_list_set_openid(mac, openId->value);
#if 0
            if (openId && openId->value) {
#else
            if (1) {
#endif
                (void)iptables_fw_allow_mac(mac);
                (void)client_list_set_auth(mac, CLIENT_VIP);
                if (config->wd_skip_SuccessPage) {
                    http_send_redirect(r, config->wd_to_url, NULL);
                } else {
                    send_onekey_success_http_page(r, mac);
                }
            } else {
                send_wechat_mess_http_page(r, "认证失败", "无法获得店铺ID");
            }
        }
        careful_free(mac);
    } else {
        send_wechat_mess_http_page(r, "认证失败", "参数错误");
    }
}

void
http_callback_wechat_redirect(httpd *webserver, request *r)
{
	httpVar *httpvar = httpdGetVariableByName(r, "type");;
    char tmp_url[MAX_BUF] = {0};
    char *url = NULL;

    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);
	url = httpdUrlEncode(tmp_url);

    debug(LOG_INFO, "url %s", url);
    if (httpvar && httpvar->value) {
        if (!memcmp(httpvar->value, "0", 1)) {
            send_wechat_pcredirect_http_page(r);
        } else {
            send_wechat_redirect_http_page(r);
        }
    }

    return;
}

void
http_callback_temppass(httpd *webserver, request *r)
{
	httpVar *httpvar = httpdGetVariableByName(r, "officialAccount");;
    char    ip[MAX_IPV4_LEN] = {0};
	char	*mac;
    time_t  current_time;
    client_t client;
    char tmp_url[MAX_BUF] = {0};
    char *url = NULL;
    s_config	*config = config_get_config();
	char *redirect_url = NULL;

    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);
	url = httpdUrlEncode(tmp_url);

    debug(LOG_INFO, "url %s", url);

#if 0
    if (httpvar && httpvar->value
        && memcmp(httpvar->value, config->wd_wechat_officialAccount, strlen(config->wd_wechat_officialAccount)) == 0) {
#else
    if (1) {
#endif
        mac = arp_get(r->clientAddr);
		if (!is_mac_valid(mac)) {
			/* We could not get their MAC address */
			debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
		} else {
		    /* We have their MAC address */
            current_time = time(NULL);
            memcpy(ip, r->clientAddr, strlen(r->clientAddr));
            memset((void *)&client, 0, sizeof(client_t));
            if (!client_list_get_client(mac, &client)) {
                if (memcmp(client.ip, r->clientAddr, strlen(r->clientAddr) + 1)) {
                    (void)client_list_set_ip(mac, r->clientAddr);
                }
                if (CLIENT_ALLOWED == client.fw_state) {
                    debug(LOG_WARNING, "find mac %s in iptables, maybe something wrong", mac);
                    (void)iptables_fw_deny_mac(mac);
                }
            } else {
                (void)client_list_add(mac);
                (void)client_list_set_ip(mac, r->clientAddr);
            }

            (void)iptables_fw_tracked_mac(mac);
            (void)iptables_fw_allow_mac(mac);
            (void)client_list_set_auth(mac, CLIENT_CHAOS);

            send_wechat_http_page(r, mac);
        }
        careful_free(mac);
	} else {
	    send_wechat_mess_http_page(r, "失败", "参数错误");
    }
    return;
}

void
http_callback_onekey_auth(httpd *webserver, request *r)
{
    char    ip[MAX_IPV4_LEN] = {0};
	char	*mac;
    time_t  current_time;
    client_t client;
    char tmp_url[MAX_BUF] = {0};
    char *url = NULL;
    s_config	*config = config_get_config();
    char tourl[MAX_RECORD_URL_LEN] = {0};

    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);
	url = httpdUrlEncode(tmp_url);

    debug(LOG_INFO, "url %s", url);

    if (1) {
        mac = arp_get(r->clientAddr);
		if (!is_mac_valid(mac)) {
			/* We could not get their MAC address */
			debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
		} else {
		    /* We have their MAC address */
            current_time = time(NULL);
            memcpy(ip, r->clientAddr, strlen(r->clientAddr));
            memset((void *)&client, 0, sizeof(client_t));
            if (!client_list_get_client(mac, &client)) {
                if (memcmp(client.ip, r->clientAddr, strlen(r->clientAddr) + 1)) {
                    (void)client_list_set_ip(mac, r->clientAddr);
                }
            } else {
                (void)client_list_add(mac);
                (void)client_list_set_ip(mac, r->clientAddr);
            }

            (void)iptables_fw_tracked_mac(mac);
            (void)iptables_fw_allow_mac(mac);
            (void)client_list_set_auth(mac, CLIENT_VIP);

            memcpy(tourl, config->wd_to_url, strlen(config->wd_to_url));
            debug(LOG_INFO, "redirect to %s", tourl);
            if (config->wd_skip_SuccessPage) {
                http_send_redirect(r, tourl, NULL);
            } else {
                send_onekey_success_http_page(r, mac);
            }
        }
        careful_free(mac);
	} else {
	    send_wechat_mess_http_page(r, "失败", "参数错误");
    }
    return;
}

void
http_callback_wechat_tradit_auth(httpd *webserver, request *r)
{
    char    ip[MAX_IPV4_LEN] = {0};
    char    *mac;
    time_t  current_time;
    client_t client;
    char tmp_url[MAX_BUF] = {0};
    char *url = NULL;
    s_config    *config = config_get_config();
    httpVar *extend = httpdGetVariableByName(r, "extend");
    httpVar *openId = httpdGetVariableByName(r, "openId");

    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);
    url = httpdUrlEncode(tmp_url);

    debug(LOG_INFO, "url %s", url);

#if 0
    if (extend && extend->value && memcmp(extend->value, config->wd_wechat_extend, strlen(config->wd_wechat_extend)) == 0) {
#else
    if (1) {
#endif
        mac = arp_get(r->clientAddr);
        if (!is_mac_valid(mac)) {
           /* We could not get their MAC address */
           debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
           send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            current_time = time(NULL);
            memcpy(ip, r->clientAddr, strlen(r->clientAddr));
            memset((void *)&client, 0, sizeof(client_t));
            if (!client_list_get_client(mac, &client)) {
                if (memcmp(client.ip, r->clientAddr, strlen(r->clientAddr) + 1)) {
                    (void)client_list_set_ip(mac, r->clientAddr);
                }
            } else {
                (void)client_list_add(mac);
                (void)client_list_set_ip(mac, r->clientAddr);
            }

            (void)iptables_fw_tracked_mac(mac);
            if (openId && openId->value) {
                (void)client_list_set_openid(mac, openId->value);
            }

            /* did not force to attention Wechat Official Accounts */
            if (config->wd_wechat_forceAttention == 0) {
                (void)iptables_fw_allow_mac(mac);
                (void)client_list_set_auth(mac, CLIENT_COMMON);
            }

            debug(LOG_WARNING, "wechat");
            send_http_page(r, "WiFiDog", "ok");
        }
            careful_free(mac);
    } else {
        debug(LOG_WARNING, "wechat invalid");
        /* did not return anything */
    }

    return;
}

void
http_callback_wechat_auth(httpd *webserver, request *r)
{
    httpVar *httpvar;
    char    ip[MAX_IPV4_LEN] = {0};
	char	*mac;
    char    appId[MAX_TOKEN_LEN] = {0};
    time_t  current_time;
    client_t client;
    char tmp_url[MAX_BUF] = {0};
    char *url = NULL;
    s_config	*config = config_get_config();

    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);
	url = httpdUrlEncode(tmp_url);

    debug(LOG_INFO, "url %s", url);

#if 0
    httpvar = httpdGetVariableByName(r, "appId");
    if (httpvar && httpvar->value) {
        memcpy(appId, httpvar->value, strlen(httpvar->value));
    }
    if (memcmp(config->wd_wechat_appId, appId, strlen(config->wd_wechat_appId)) == 0) {
#else
    if (1) {
#endif
        mac = arp_get(r->clientAddr);
		if (!is_mac_valid(mac)) {
			/* We could not get their MAC address */
			debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
		} else {
		    /* We have their MAC address */
            current_time = time(NULL);
            memcpy(ip, r->clientAddr, strlen(r->clientAddr));
            memset((void *)&client, 0, sizeof(client_t));
            if (!client_list_get_client(mac, &client)) {
                if (memcmp(client.ip, r->clientAddr, strlen(r->clientAddr) + 1)) {
                    (void)client_list_set_ip(mac, r->clientAddr);
                }
            } else {
                (void)client_list_add(mac);
                (void)client_list_set_ip(mac, r->clientAddr);
            }

            (void)iptables_fw_tracked_mac(mac);

            if (config->wd_auth_mode == AUTH_SERVER_XIECHENG) {
                httpVar *tokenVar = httpdGetVariableByName(r, "token");
                if (tokenVar && tokenVar->value) {
                    char openid[MAX_OPENID_LEN] = {0};
                    char token[MAX_TOKEN_LEN] = {0};
                    memcpy(token, tokenVar->value, strlen(tokenVar->value));
                    if (config->pad_token && client_list_get_openid(mac, openid) == RET_SUCCESS) {
                        if (strcasecmp(openid, DUMY_OPENID)) {
                            strcat(token, openid);
                        }
                    }
                    (void)client_list_set_token(mac, token);
                }
                authenticate_client(mac, r);
            } else {
                (void)iptables_fw_allow_mac(mac);
                (void)client_list_set_auth(mac, CLIENT_VIP);
                if (config->wd_skip_SuccessPage) {
                    http_send_redirect(r, config->wd_to_url, NULL);
                } else {
                    send_wechat_success_http_page(r, mac);
                }
            }
        }
        careful_free(mac);
	} else {
	    send_wechat_mess_http_page(r, "认证失败", "参数错误");
    }
}

void send_http_page(request *r, const char *title, const char* message)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd=open(config->htmlmsgfile, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written]=0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}

void send_wechat_http_page(request *r, const char *mac)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/wechat.html";
    char port[32] = {0};
    char buf[33] = {0};

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    if (config->wd_wechat_shopId && strlen(config->wd_wechat_shopId)) {
        httpdAddVariable(r, "shopId", config->wd_wechat_shopId); //"6213511");
    }
    if (config->wd_wechat_appId && strlen(config->wd_wechat_appId)) {
        httpdAddVariable(r, "appId", config->wd_wechat_appId); //"wx965dbd48e9638e29");//
    }
    if (config->wd_wechat_secretKey && strlen(config->wd_wechat_secretKey)) {
        httpdAddVariable(r, "secretKey", config->wd_wechat_secretKey);//"11d2d4b860ca817799778f312a0d16ba");//
    }
    if (config->gw_address && strlen(config->gw_address)) {
        httpdAddVariable(r, "gw_address", config->gw_address);
    }
    sprintf(port, "%d", config->gw_port);
    httpdAddVariable(r, "gw_port", port);
    if (mac && strlen(mac)) {
        httpdAddVariable(r, "mac", mac);
    }
#ifdef __MTK_SDK__
    if (bl_get_config("WlanSSID", buf)) {
        memcpy(buf, "ssid", strlen("myWifi"));
    }
#else
    memcpy(buf, "ssid", strlen("myWifi"));//xxxc
#endif
    httpdAddVariable(r, "ssid", buf);
    memset(buf, 0, sizeof(buf) / sizeof (buf[0]));
    if (getIfMac("ra0", buf)) {
        memcpy(buf, "00:0C:43:76:20:66", strlen("00:0C:43:76:20:66"));
    }
    httpdAddVariable(r, "bssid", buf);

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_wechat_pc_http_page(request *r)
{
    s_config    *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/wechat_pc.html";
    char port[32] = {0};

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    httpdAddVariable(r, "shopId", config->wd_wechat_shopId); //"6213511");
    httpdAddVariable(r, "appId", config->wd_wechat_appId); //"wx965dbd48e9638e29");//
    httpdAddVariable(r, "gw_address", config->gw_address);
    sprintf(port, "%d", config->gw_port);
    httpdAddVariable(r, "gw_port", port);

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_onekey_redirect_http_page(request *r)
{
    s_config    *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = NULL;
    char port[32] = {0};

    if (config->wd_auth_mode == AUTH_LOCAL_ONEKEY_AUTO) {
        wechat_file = "/etc_ro/wechat/onekey_auto.html";
    } else {
        wechat_file = "/etc_ro/wechat/onekey_manual.html";
    }

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    sprintf(port, "%d", config->gw_port);
    if (config->gw_address && strlen(config->gw_address)) {
        httpdAddVariable(r, "gw_address", config->gw_address);
    }
    httpdAddVariable(r, "gw_port", port);

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_wechat_check_http_page(request *r)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/wechat_check.html";
    char port[32] = {0};

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    if (config->gw_address && strlen(config->gw_address)) {
        httpdAddVariable(r, "gw_address", config->gw_address);
    }
    sprintf(port, "%d", config->gw_port);
    httpdAddVariable(r, "gw_port", port);

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_wechat_redirect_http_page(request *r)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/wechat_redirect.html";
    char port[32] = {0};

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    if (config->wd_wechat_officialAccount && strlen(config->wd_wechat_officialAccount)) {
        httpdAddVariable(r, "officialAccount", config->wd_wechat_officialAccount);
    }
    if (config->gw_address && strlen(config->gw_address)) {
        httpdAddVariable(r, "gw_address", config->gw_address);
    }
    sprintf(port, "%d", config->gw_port);
    httpdAddVariable(r, "gw_port", port);

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_wechat_pcredirect_http_page(request *r)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/wechat_pcredirect.html";
    char port[32] = {0};

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    if (config->wd_wechat_officialAccount && strlen(config->wd_wechat_officialAccount)) {
        httpdAddVariable(r, "officialAccount", config->wd_wechat_officialAccount);
    }
    if (config->gw_address && strlen(config->gw_address)) {
        httpdAddVariable(r, "gw_address", config->gw_address);
    }
    sprintf(port, "%d", config->gw_port);
    httpdAddVariable(r, "gw_port", port);

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_wechat_success_http_page(request *r, const char *mac)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/wechat_success.html";

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    if (config->wd_to_url && strlen(config->wd_to_url)) {
        httpdAddVariable(r, "recent_req", config->wd_to_url);
    }
#if SUCCESS_TO_RECENT_URL
    if (client_list_get_recent_req(mac, recent_req) != RET_SUCCESS) {
        memcpy(recent_req, DUMY_REQ_URL, strlen(DUMY_REQ_URL) + 1);
    }
    httpdAddVariable(r, "recent_req", recent_req);
#endif

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_onekey_success_http_page(request *r, const char *mac)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/onekey_success.html";
    char tourl[MAX_RECORD_URL_LEN] = {0};

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    memcpy(tourl, config->wd_to_url, strlen(config->wd_to_url));
#if SUCCESS_TO_RECENT_URL
    memset(tourl, 0, sizeof(tourl) / sizeof(tourl[0]));
    if (client_list_get_recent_req(mac, tourl) != RET_SUCCESS) {
        memcpy(tourl, DUMY_REQ_URL, strlen(DUMY_REQ_URL) + 1);
    }
#endif
    debug(LOG_INFO, "redirect to %s", tourl);
    if (tourl && strlen(tourl)) {
        httpdAddVariable(r, "recent_req", tourl);
    }

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_wechat_fail_http_page(request *r)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/wechat_fail.html";

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void send_wechat_mess_http_page(request *r, const char *title, const char* message)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    const static char *wechat_file = "/etc_ro/wechat/wechat_mess.html";

    fd=open(wechat_file, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML wechat file %s: %s", wechat_file, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML wechat file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML wechat file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);
    buffer[written]=0;

    if (title && strlen(title)) {
        httpdAddVariable(r, "title", title);
    }
    if (message && strlen(message)) {
        httpdAddVariable(r, "message", message);
    }

    httpdOutput(r, buffer);
    careful_free(buffer);
}

void http_callback_shumo(httpd * webserver,request * r)
{
    char allow[HTTP_MAX_URL] = {0};
	char duration[HTTP_MAX_URL] = {0};
	char redirect_url[HTTP_MAX_URL] = {0};
	char *mac = NULL;
	char tmp_url[MAX_BUF] = {0};
	httpVar *httpvar;
	time_t current_time;
	char *url = NULL;
	snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);

    debug(LOG_INFO, "url %s", tmp_url);
	if(httpvar = httpdGetVariableByName(r, "allow")){
	    memcpy(allow, httpvar->value, strlen(httpvar->value));
	}

	if(httpvar = httpdGetVariableByName(r, "duration")){
	    memcpy(duration, httpvar->value, strlen(httpvar->value));
	}

	if(httpvar = httpdGetVariableByName(r, "redirect")){
	    memcpy(redirect_url, httpvar->value, strlen(httpvar->value));
	}
	current_time = time(NULL);

	debug(LOG_INFO, "CLIENT MAC ADDRES %s", r->clientAddr);

	mac = arp_get(r->clientAddr);

    /* allow the iphones */
    if (strlen(allow) && (atoi(allow) == 1)) {
        (void)client_list_set_auth(mac, CLIENT_CHAOS);
        (void)iptables_fw_allow_mac(mac);
        if (strlen(duration) && (atoi(duration) != 0)) {
            (void)client_list_set_allow_time(mac, current_time);
            (void)client_list_set_duration(mac, atoi(duration));
        }
        (void)iptables_fw_tracked_mac(mac);
        (void)client_list_set_last_updated(mac, current_time);
    }
	debug(LOG_INFO, "redirect_url is %s", redirect_url);
	url = strstr(tmp_url, "redirect");
	if(url != NULL){
	    http_send_redirect(r, url+9, NULL);
	}
	careful_free(mac);

}

void http_callback_appdl(httpd *webserver, request *r)
{
    time_t  current_time;
    char tmp_url[MAX_BUF] = {0};
    s_config    *config = config_get_config();
    httpVar *httpvar;
    char appid[HTTP_MAX_URL] = {0};
    char type[HTTP_MAX_URL] = {0};
    char allow[HTTP_MAX_URL] = {0};
    char duration[HTTP_MAX_URL] = {0};
    char route_mac[HTTP_MAX_URL] = {0};
    char dev[HTTP_MAX_URL] = {0};
    char appurl[HTTP_MAX_URL] = {0};
    char mac[MAC_ADDR_LEN] = {0};
    char concat[HTTP_MAX_URL] = {0};

    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
    r->request.host,
    r->request.path,
    r->request.query[0] ? "?" : "",
    r->request.query);

    debug(LOG_INFO, "url %s", tmp_url);

    if ((httpvar = httpdGetVariableByName(r, "appid"))) {
        memcpy(appid, httpvar->value, strlen(httpvar->value));
    }
    if ((httpvar = httpdGetVariableByName(r, "type"))) {
        memcpy(type, httpvar->value, strlen(httpvar->value));
    }
    if ((httpvar = httpdGetVariableByName(r, "allow"))) {
        memcpy(allow, httpvar->value, strlen(httpvar->value));
    }
    if ((httpvar = httpdGetVariableByName(r, "duration"))) {
        memcpy(duration, httpvar->value, strlen(httpvar->value));
    }
    if ((httpvar = httpdGetVariableByName(r, "mac"))) {
        memcpy(route_mac, httpvar->value, strlen(httpvar->value));
    }
    if ((httpvar = httpdGetVariableByName(r, "dev"))) {
        memcpy(dev, httpvar->value, strlen(httpvar->value));
        (void)id_to_mac(mac, dev);
    }
    current_time = time(NULL);

    if (!strlen(appid)) {
        send_wechat_mess_http_page(r, "无法下载", "未知的app编号");
        return;
    }

    /* allow the iphones */
    if (strlen(allow) && (atoi(allow) == 1)) {
        (void)client_list_set_auth(mac, CLIENT_CHAOS);
        (void)iptables_fw_allow_mac(mac);
        if (strlen(duration) && (atoi(duration) != 0)) {
            (void)client_list_set_allow_time(mac, current_time);
            (void)client_list_set_duration(mac, atoi(duration));
        }
        (void)iptables_fw_tracked_mac(mac);
        (void)client_list_set_last_updated(mac, current_time);
    }

    /* get md5 */
    appctl_appurl(appurl, appid);
    sprintf(concat, "&mac=%s&dev=%s&tm=%u", route_mac, dev, current_time);

    /* check md5 and return result */
    if (strlen(appurl) < 3) {
        send_wechat_mess_http_page(r, "无法下载", "无法校验结果");
    } else if (strstr(appurl, "fail.html") != NULL) {
        strcat(appurl, concat);
        http_send_redirect(r, appurl, NULL);
    } else {
        (void)click_record_queue_enqueue(appid, mac, atoi(type), current_time); /* record */
        strcat(appurl, concat);
        http_send_redirect(r, appurl, NULL);
    }
}

