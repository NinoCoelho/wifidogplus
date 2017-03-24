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

/*
 * $Id$
 */
/** @internal
  @file firewall.c
  @brief Firewall update functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  2006 Benoit Grégoire, Technologies Coeus inc. <bock@step.polymtl.ca>
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>

#ifdef __linux__
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#endif

#if defined(__NetBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

#include "common.h"
#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "centralserver.h"
#include "client_list.h"
#include "list.h"
#include "watchdog.h"
#include "qos.h"
#include "wifiga_ubus_client.h"
#include "counterfeit.h"


extern int fw_rebuild_flag;

/* from commandline.c */
extern pid_t restart_orig_pid;


/**
 * Allow a client access through the firewall by adding a rule in the firewall to MARK the user's packets with the proper
 * rule by providing his IP and MAC address
 * @param ip IP address to allow
 * @param mac MAC address to allow
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_allow(const char *ip, const char *mac, int fw_connection_state)
{
    debug(LOG_DEBUG, "Allowing %s %s with fw_connection_state %d", ip, mac, fw_connection_state);

    return iptables_fw_access(FW_ACCESS_ALLOW, ip, mac, fw_connection_state);
}

/**
 * @brief Deny a client access through the firewall by removing the rule in the firewall that was fw_connection_stateging the user's traffic
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_deny(const char *ip, const char *mac, int fw_connection_state)
{
    debug(LOG_DEBUG, "Denying %s %s with fw_connection_state %d", ip, mac, fw_connection_state);

    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, fw_connection_state);
}

/* XXX DCY */
/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char           *
arp_get(const char *req_ip)
{
    FILE           *proc;
	 char ip[16] = {0};
	 char mac[18] = {0};
	 char * reply = NULL;

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }

    /* Skip first line */
	 while (!feof(proc) && fgetc(proc) != '\n');

	 /* Find ip, copy mac in reply */
	 reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		  if (strcmp(ip, req_ip) == 0) {
				reply = safe_strdup(mac);
				break;
		  }
    }

    fclose(proc);

    return reply;
}

char           *
rarp_get(const char *req_mac)
{
    FILE           *proc;
    char ip[16];
    char mac[MAC_ADDR_LEN];
    char * reply = NULL;

#if _CHECK_CAREFUL_
    if (!is_mac_valid(req_mac)) {
        return NULL;
    }
#endif

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        debug(LOG_DEBUG, "fail to open arp file");
        return NULL;
    }

    /* Skip first line */
    while (!feof(proc) && fgetc(proc) != '\n');

    /* Find ip, copy mac in reply */
    reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
        if (strncasecmp(mac, req_mac, MAC_ADDR_LEN) == 0) {
            reply = safe_strdup(ip);
            break;
        }
    }

    fclose(proc);

    return reply;
}

char * arp_get_interface(const char *req_mac)
{
    FILE           *proc;
    char interface[16];
    char mac[MAC_ADDR_LEN];
    char * reply = NULL;

#if _CHECK_CAREFUL_
    if (!is_mac_valid(req_mac)) {
        return NULL;
    }
#endif

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        debug(LOG_DEBUG, "fail to open arp file");
        return NULL;
    }

    /* Skip first line */
    while (!feof(proc) && fgetc(proc) != '\n');

    /* Find ip, copy mac in reply */
    reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %*s %*s %*s %17[A-Fa-f0-9:] %*s %s", mac, interface) == 2)) {
        if (strncasecmp(mac, req_mac, MAC_ADDR_LEN) == 0) {
            reply = safe_strdup(interface);
            break;
        }
    }

    fclose(proc);

    return reply;
}

/** Initialize the firewall rules
 */
int
fw_init(void)
{
#if WIFIDOG_ON_OFF
    int flags, oneopt = 1, zeroopt = 0;
	 int result = 0;

    debug(LOG_INFO, "Creating ICMP socket");
    if ((icmp_fd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
            (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
             fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
             setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
             setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
        debug(LOG_ERR, "Cannot create ICMP raw socket.");
        return 0;
    }

    debug(LOG_INFO, "Initializing Firewall");
    result = iptables_fw_init();

    if (restart_orig_pid || fw_rebuild_flag) {
        debug(LOG_INFO, "Restoring firewall rules for clients inherited from parent");
        if(fw_backup_from_client_list()) {
            debug(LOG_ERR, "fail to restore iptables rules");
        }
	 } else {
        (void)fw_backup_from_file();
	 }

    if (config_get_config()->qosEnable) {
        execute_cmd("qos-init.sh", NULL);
    }

	 return result;
#endif
}

/** Remove all auth server firewall whitelist rules
 */
void
fw_clear_authservers(void)
{
	debug(LOG_INFO, "Clearing the authservers list");
	iptables_fw_clear_authservers();
}

/** Add the necessary firewall rules to whitelist the authservers
 */
void
fw_set_authservers(void)
{
	debug(LOG_INFO, "Setting the authservers list");
	iptables_fw_set_authservers();
}

/** Remove all app server firewall whitelist rules
 */
void
fw_clear_appservers(void)
{
	debug(LOG_INFO, "Clearing the appservers list");
	iptables_fw_clear_appservers();
}

/** Add the necessary firewall rules to whitelist the appservers
 */
void
fw_set_appservers(void)
{
	debug(LOG_INFO, "Setting the appservers list");
	iptables_fw_set_appservers();
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
#if WIFIDOG_ON_OFF
    if (icmp_fd != 0) {
        debug(LOG_INFO, "Closing ICMP socket");
        close(icmp_fd);
    }

    debug(LOG_INFO, "Removing Firewall rules");
    return iptables_fw_destroy();
#endif
}

static int fw_sync_condition(const client_t *client, void *args)
{
#if _CHECK_CAREFUL_
    if (!client) {
        return 0;
    }
#endif

    /* did not need to sysc with authserver which MAC in config and offline client */
    if (client->auth >= CLIENT_CONFIG) {
        return 0;
    }

    return 1;
}

static void del_client(const char *mac)
{
#if _CHECK_CAREFUL_
    if (!is_mac_valid(mac))
    {
        return;
    }
#endif

    (void)iptables_fw_deny_mac(mac);
    (void)iptables_fw_untracked_mac(mac);
    (void)client_list_del(mac);
}

/* delete some client that did not need autu */
void del_free_certification_client(void)
{
    typedef struct client_node_s {
        struct dlist_head   list;
        char                mac[MAC_ADDR_LEN];
        char                intf[MAX_INTERFACE_NAME_LEN];
    } client_node_t;

    FILE           *proc;
    char intf[MAX_INTERFACE_NAME_LEN] = {0};
    char mac[MAC_ADDR_LEN] = {0};
    DLIST_HEAD(auth_device_client_list);
    DLIST_HEAD(unauth_device_client_list);
    client_node_t *pos, *pos_tmp, *pos1;

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        debug(LOG_DEBUG, "fail to open arp file");
        return;
    }

    /* Skip first line */
    while (!feof(proc) && fgetc(proc) != '\n');
    while (!feof(proc) && (fscanf(proc, " %*s %*s %*s %17[A-Fa-f0-9:] %*s %s", mac, intf) == 2)) {
        debug(LOG_DEBUG, "arp found mac %s, interface %s", mac, intf);
        client_node_t *new_node = (client_node_t *)safe_malloc(sizeof(client_node_t));
        memcpy(new_node->mac, mac, MAC_ADDR_LEN);
        memcpy(new_node->intf, intf, MAX_INTERFACE_NAME_LEN);

        if (strncasecmp(new_node->intf, config_get_config()->gw_interface,
            strlen(config_get_config()->gw_interface) + 1) == 0) {
            dlist_add(&new_node->list, &auth_device_client_list);
        } else {
            dlist_add(&new_node->list, &unauth_device_client_list);
        }

        memset(mac, 0, MAC_ADDR_LEN);
        memset(intf, 0, MAX_INTERFACE_NAME_LEN);
        continue;
    }
    fclose(proc);

    dlist_for_each_entry_safe(pos, pos_tmp, &unauth_device_client_list, client_node_t, list) {
        dlist_for_each_entry(pos1, &auth_device_client_list, client_node_t, list) {
            if (strncasecmp(pos->mac, pos1->mac, MAC_ADDR_LEN) == 0) {
                debug(LOG_DEBUG, "mac %s exist in interface %s and interface %s, did not need to del",
                    pos->mac, pos->intf, pos1->intf);
                dlist_del(&pos->list);
                careful_free(pos);
                break;
            }
        }
    }

    dlist_for_each_entry_safe(pos, pos_tmp, &unauth_device_client_list, client_node_t, list) {
        debug(LOG_DEBUG, "delete mac %s which in the interface %s", pos->mac, pos->intf);
        del_client(pos->mac);
        dlist_del(&pos->list);
        careful_free(pos);
    }

    dlist_for_each_entry_safe(pos, pos_tmp, &auth_device_client_list, client_node_t, list) {
        dlist_del(&pos->list);
        careful_free(pos);
    }
}

#ifdef THIS_THREAD_NAME
#undef THIS_THREAD_NAME
#endif
#define THIS_THREAD_NAME    THREAD_FW_COUNTER_NAME
/**Probably a misnomer, this function actually refreshes the entire client list's traffic counter, re-authenticates every client with the central server and update's the central servers traffic counters and notifies it if a client has logged-out.
 * @todo Make this function smaller and use sub-fonctions
 */
void
fw_sync_with_authserver(void)
{
    struct dlist_head client_traverse_list = LIST_HEAD_INIT(client_traverse_list);
    client_hold_t *pos, *pos_tmp;
    t_authresponse  authresponse;
    s_config *config = config_get_config();
    int count = 0;
    int auth;
    unsigned int fw_state;
    client_list_hold_t hold;
    time_t current_time = time(NULL);
    static int certification;

#if _CHECK_CAREFUL_
    (void)del_free_certification_client();
    if (current_time > MINIMUM_STARTED_TIME && certification == 0) {
        (void)client_list_calibration_time();
        certification = 1;
    }
#endif

    if (-1 == iptables_fw_counters_update()) {
        debug(LOG_ERR, "Could not get counters from firewall!");
        return;
    }
    (void)pthread_watchdog_feed(THIS_THREAD_NAME);

    /* backup the client list to client_traverse_list */
    hold.head = &client_traverse_list;
    hold.func = fw_sync_condition;
    hold.args = NULL;
    if (client_list_traverse((CLIENT_LIST_TRAVERSE_FUNC)client_list_hold, &hold)) {
        client_list_destory_hold(&hold);
        debug(LOG_ERR, "fail to create client_traverse_list");
        return;
    }

    /* sync with authserver, using client_traverse_list */
    dlist_for_each_entry(pos, &client_traverse_list, client_hold_t, list) {
        if (!client_list_is_exist(pos->client.mac)) {
            debug(LOG_ERR, "Node %s was freed while being re-validated!", pos->client.mac);
            continue;
        }
        OVERFLOW_FEED(THIS_THREAD_NAME, count, MAX_DO_COMMAND_CONTINUE);
        debug(LOG_DEBUG, "pos ip %s, mac %s, token %s",
            pos->client.ip, pos->client.mac, pos->client.token);

        /* check ip is valid */
        if (!memcmp(pos->client.ip, DUMY_IP, strlen(DUMY_IP) + 1) || !is_ip_valid(pos->client.ip)) {
            char *real_ip = NULL;
            debug(LOG_DEBUG, "mac %s ip is invaild, getting valid ip", pos->client.mac);
            real_ip = rarp_get(pos->client.mac);
            if (is_ip_valid(real_ip)) {
                char find_mac[MAC_ADDR_LEN] = {0};
                if (!client_list_find_mac_by_ip_exclude(real_ip, pos->client.mac, find_mac)) {
                    /* DHCP had given this ip to a new client */
                    if (strncasecmp(pos->client.mac, find_mac, MAC_ADDR_LEN)) {
                        (void)client_list_set_ip(find_mac, DUMY_IP);
                    }
                }

                debug(LOG_DEBUG, "mac[%s] ,real_ip[%s] ", pos->client.mac, real_ip);
                (void)client_list_set_ip(pos->client.mac, real_ip);
                (void)iptables_fw_tracked_mac(pos->client.mac);
                memset(pos->client.ip, 0, MAX_IPV4_LEN);
                memcpy(pos->client.ip, real_ip, MAX_IPV4_LEN);
            }
            careful_free(real_ip);
        }

        if (config->qosEnable) {
            do_qos(pos->client.mac);
        }

#if 0
        /* Ping the client, if he responds it'll keep activity on the link.
         * However, if the firewall blocks it, it will not help.  The suggested
         * way to deal witht his is to keep the DHCP lease time extremely
         * short:  Shorter than config->checkinterval * config->clienttimeout
         */
        if (memcmp(pos->client.ip, DUMY_IP, strlen(DUMY_IP) + 1)) {
            debug(LOG_DEBUG, "ping ip[%s]", pos->client.ip);
            icmp_ping(pos->client.ip);
        }
#endif

        if (!client_list_is_connect_really(pos->client.mac)) {
            /* the client live this router for a long time, remove the cache */
            if (pos->client.auth >= CLIENT_VIP) {
                if (current_time - pos->client.counters.last_updated
                    > (CLIENT_LIVE_TIME_VIP  + config->clienttimeout) * config->checkinterval) {
                    debug(LOG_INFO, "[%s] time out, remove the cache", pos->client.mac);
                    (void)iptables_fw_deny_mac(pos->client.mac);
                    (void)iptables_fw_untracked_mac(pos->client.mac);
                    client_list_del(pos->client.mac);
                    continue;
                }
            } else if (pos->client.auth >= CLIENT_COMMON) {
                if (current_time - pos->client.counters.last_updated
                    > (CLIENT_LIVE_TIME_COMMON + config->clienttimeout) * config->checkinterval) {
                    debug(LOG_INFO, "[%s] time out, remove the cache", pos->client.mac);
                    (void)iptables_fw_deny_mac(pos->client.mac);
                    (void)iptables_fw_untracked_mac(pos->client.mac);
                    client_list_del(pos->client.mac);
                    continue;
                }
            } else {
                if (current_time - pos->client.counters.last_updated
                    > (CLIENT_LIVE_TIME_UNAUTH + config->clienttimeout) * config->checkinterval) {
                    debug(LOG_INFO, "[%s] time out, remove the cache", pos->client.mac);
                    (void)iptables_fw_deny_mac(pos->client.mac);
                    (void)iptables_fw_untracked_mac(pos->client.mac);
                    client_list_del(pos->client.mac);
                    continue;
                }
            }

            debug(LOG_INFO, "Checking client %s for timeout:  Last updated %ld (%ld seconds ago), timeout delay %ld seconds, current time %ld, ",
                pos->client.ip, pos->client.counters.last_updated, current_time - pos->client.counters.last_updated,
                config->checkinterval * config->clienttimeout, current_time);
            /* Timing out user */
            (void)iptables_fw_deny_mac(pos->client.mac);
            (void)iptables_fw_untracked_mac(pos->client.mac);
            if (config->audit_enable && pos->client.onoffline == CLIENT_ONLINE) {
                (void)report_onoffline(pos->client.mac, CLIENT_OFFLINE);
                (void)client_list_set_onoffline(pos->client.mac, CLIENT_OFFLINE);
            }

            /* Advertise the logout if we have an auth server
            * cjpthree: change to did not advertise auth server, only do this thing local
            */
#if 0
            if (config->auth_servers != NULL) {
                debug(LOG_DEBUG, "Advertise auth server that %s logout", pos->client.mac);
				auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT,
                    pos->client.ip, pos->client.mac, pos->client.token, 0, 0);
            }
#endif
            continue;
        }
        else { /* client_list_is_connect_really(pos->client.mac) */
            /* local auth mode, timeout client */
            if (IS_LOCAL_AUTH(config->wd_auth_mode)) {
                if (pos->client.fw_state == CLIENT_ALLOWED) {
                    unsigned int remain = 0;
                    (void)client_list_get_remain_allow_time(pos->client.mac, &remain);
                    if (remain <= 0) {
                        debug(LOG_INFO, "deny %s", pos->client.mac);
                        (void)iptables_fw_deny_mac(pos->client.mac);
                        continue;
                    }
                }
            }
            /*
             * This handles any change in
             * the status this allows us
             * to change the status of a
             * user while he's connected
             *
             * Only run if we have an auth server
             * configured!
             */
            else if (config->auth_servers != NULL) {
                /* Update the counters on the remote server only if we have an auth server */
                auth_server_request(&authresponse, REQUEST_TYPE_COUNTERS,
                    pos->client.ip, pos->client.mac, pos->client.token,
                    pos->client.counters.incoming, pos->client.counters.outgoing);
                switch (authresponse.authcode) {
                    case AUTH_DENIED:
                        debug(LOG_NOTICE, "%s - Denied. Removing client and firewall rules", pos->client.mac);
                        if (client_list_get_auth(pos->client.mac, &auth)) {
                            auth = CLIENT_UNAUTH;
                        }
                        if (auth >= CLIENT_CONFIG) {
                            debug(LOG_DEBUG, "mac %s is in config, can not delete", pos->client.mac);
                            break;
                        }
                        (void)client_list_set_auth(pos->client.mac, CLIENT_UNAUTH);
                        (void)iptables_fw_deny_mac(pos->client.mac);
                        break;

                    case AUTH_VALIDATION_FAILED:
                        debug(LOG_NOTICE, "%s - Validation timeout, now denied. Removing client and firewall rules", pos->client.mac);
                        if (client_list_get_auth(pos->client.mac, &auth)) {
                            auth = CLIENT_UNAUTH;
                        }
                        if (auth >= CLIENT_CONFIG) {
                            debug(LOG_DEBUG, "mac %s is in config, can not delete", pos->client.mac);
                            break;
                        }
                        (void)client_list_set_auth(pos->client.mac, CLIENT_UNAUTH);
                        (void)iptables_fw_deny_mac(pos->client.mac);
                        break;

                    case AUTH_ALLOWED:
                        (void)client_list_set_auth(pos->client.mac, CLIENT_COMMON);
                        (void)iptables_fw_allow_mac(pos->client.mac);
                        break;

					case AUTH_VIP:
                        (void)client_list_set_auth(pos->client.mac, CLIENT_VIP);
                        (void)iptables_fw_allow_mac(pos->client.mac);
						break;
                    case AUTH_VALIDATION:
                        /*
                         * Do nothing, user
                         * is in validation
                         * period
                         */
                        debug(LOG_INFO, "%s - User in validation period", pos->client.mac);
                        break;

                    case AUTH_ERROR:
                        debug(LOG_WARNING, "Error communicating with auth server - leaving %s as-is for now", pos->client.mac);
                        break;

                    default:
                        debug(LOG_ERR, "I do not know about authentication code %d", authresponse.authcode);
                        break;
                }
            }
        }
    }

    client_list_destory_hold(&hold);
    return;
}
#ifdef THIS_THREAD_NAME
#undef THIS_THREAD_NAME
#endif

void
icmp_ping(const char *host)
{
	struct sockaddr_in saddr;
#if defined(__linux__) || defined(__NetBSD__)
	struct {
		struct ip ip;
		struct icmp icmp;
	} packet;
#endif
	unsigned int i, j;
	int opt = 2000;
	unsigned short id = rand16();

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	inet_aton(host, &saddr.sin_addr);
#if defined(HAVE_SOCKADDR_SA_LEN) || defined(__NetBSD__)
	saddr.sin_len = sizeof(struct sockaddr_in);
#endif

#if defined(__linux__) || defined(__NetBSD__)
	memset(&packet.icmp, 0, sizeof(packet.icmp));
	packet.icmp.icmp_type = ICMP_ECHO;
	packet.icmp.icmp_id = id;

	for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
		j += ((unsigned short *)&packet.icmp)[i];

	while (j >> 16)
		j = (j & 0xffff) + (j >> 16);

	packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

	if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
		debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

	if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0,
	           (const struct sockaddr *)&saddr, sizeof(saddr)) == -1)
		debug(LOG_ERR, "sendto(): %s", strerror(errno));

	opt = 1;
	if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
		debug(LOG_ERR, "setsockopt(): %s", strerror(errno));
#endif

	return;
}

unsigned short rand16(void) {
  static int been_seeded = 0;

  if (!been_seeded) {
    unsigned int seed = 0;
    struct timeval now;

    /* not a very good seed but what the heck, it needs to be quickly acquired */
    gettimeofday(&now, NULL);
    seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

    srand(seed);
    been_seeded = 1;
    }

    /* Some rand() implementations have less randomness in low bits
     * than in high bits, so we only pay attention to the high ones.
     * But most implementations don't touch the high bit, so we
     * ignore that one.
     **/
      return( (unsigned short) (rand() >> 15) );
}
