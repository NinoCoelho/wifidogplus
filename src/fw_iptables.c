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
/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"
#include "list.h"

#define ONE_COMAND_MAX_LENGTH (128UL)

static char *iptables_compile(const char *, const char *, const t_firewall_rule *);
static void iptables_load_ruleset(const char *, const char *, const char *);

extern pthread_mutex_t	config_mutex;

/**
Used to supress the error output of the firewall during destruction */
static int fw_quiet = 0;

/** @internal
 * @brief Insert $ID$ with the gateway's id in a string.
 *
 * This function can replace the input string with a new one. It assumes
 * the input string is dynamically allocted and can be free()ed safely.
 *
 * This function must be called with the CONFIG_LOCK held.
 */
static void
iptables_insert_gateway_id(char **input)
{
	char *token;
	const s_config *config;
	char *buffer;

	if (strstr(*input, "$ID$")==NULL)
		return;


	while ((token=strstr(*input, "$ID$"))!=NULL)
		/* This string may look odd but it's standard POSIX and ISO C */
		memcpy(token, "%1$s", 4);

	config = config_get_config();
	safe_asprintf(&buffer, *input, config->gw_interface);

	free(*input);
	*input=buffer;
}

/* Whether a iptables command is running failure */
static int is_iptables_command_fail(char* cmd, char *result)
{
    typedef struct exclude_s {
        char cmd_fragment[ONE_COMAND_MAX_LENGTH];
        char result_fragment[ONE_COMAND_MAX_LENGTH];
    } exclude_t;

    int i;
    int j;
    static char fail_arry[][ONE_COMAND_MAX_LENGTH] = {
        "not found",
        "No chain/target/match by that name",
        "holding the xtables lock",
        "bad rate",
        /*"Target problem",
        "Bad built-in chain name",
        "Bad policy name",
        "Will be implemented real soon."*/};
    exclude_t exclude_arry[] = {
        {"-D", "No chain/target/match by that name"},
        {"-F", "No chain/target/match by that name"},
        {"-X", "No chain/target/match by that name"},
        {"-Z", "No chain/target/match by that name"},
        {"-L", "No chain/target/match by that name"}};

    if (!cmd || !strlen(cmd) || !result || !strlen(result)) {
        return 0;
    }

    for (i = 0; i < sizeof(fail_arry) / sizeof(fail_arry[0]); i++) {
        if (strlen(fail_arry[i]) && strstr(result, fail_arry[i])) {
            for (j = 0; j < sizeof(exclude_arry) / sizeof(exclude_arry[0]); j++) {
                //debug(LOG_DEBUG, "j %d: cmd %s cmd_fragment %s, result %s result_fragment %s",
                    //j, cmd, exclude_arry[j].cmd_fragment, result, exclude_arry[j].result_fragment);
                if (strstr(cmd, exclude_arry[j].cmd_fragment) && strstr(result, exclude_arry[j].result_fragment)) {
                    //debug(LOG_DEBUG, "found %s and %s in result, need not to do command again",
                        //exclude_arry[j].cmd_fragment, exclude_arry[j].result_fragment);
                    return 0;
                }
            }

            return 1;
        }
    }

    return 0;
}

#ifdef __MTK_SDK__
int
iptables_do_command_not_care(const char *format, ...)
{
	va_list vlist;
	char *fmt_cmd;
	char *cmd;
	int rc;
    char result[MAX_BUF] = {0};
    int retry = 0;

	va_start(vlist, format);
	safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);

#if IPTABELES_VESION > (1421)
	safe_asprintf(&cmd, "iptables %s %s", fmt_cmd, "-w");
#else
    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
#endif /* IPTABELES_VESION */
	careful_free(fmt_cmd);

	iptables_insert_gateway_id(&cmd);
	debug(LOG_DEBUG, "Executing command: %s", cmd);

    execute_not_care(cmd, 0);

	careful_free(cmd);
	return rc;
}
#endif

/** @internal
 * */
int
iptables_do_command(const char *format, ...)
{
	va_list vlist;
	char *fmt_cmd;
	char *cmd;
	int rc;
    char result[MAX_BUF] = {0};
    int retry = 0;

	va_start(vlist, format);
	safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);
#ifdef __OPENWRT__
#if IPTABELES_VESION > (1421)
	safe_asprintf(&cmd, "iptables %s %s", fmt_cmd, "-w 2>&1");
#else
    safe_asprintf(&cmd, "iptables %s %s", fmt_cmd, "2>&1");
#endif /* IPTABELES_VESION */
#endif /* __OPENWRT__ */
#ifdef __MTK_SDK__
#if IPTABELES_VESION > (1421)
	safe_asprintf(&cmd, "iptables %s %s", fmt_cmd, "-w");
#else
    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
#endif /* IPTABELES_VESION */
#endif /* __MTK_SDK__ */
	careful_free(fmt_cmd);

	iptables_insert_gateway_id(&cmd);
	debug(LOG_DEBUG, "Executing command: %s", cmd);

DO_COMMAND:
    memset(result, 0, sizeof(result) / sizeof(result[0]));
#ifdef __OPENWRT__
    rc = execute_cmd(cmd, result);
#endif
#ifdef __MTK_SDK__
    rc = execute_cmd(cmd, NULL);
#endif
	if (rc!=0) {
        if (++retry < RETRY_MAX_TIME) {
            debug(LOG_DEBUG, "do this command a again");
            sleep(1);
            goto DO_COMMAND;
        }
    }
    if (strlen(result)) {
        debug(LOG_DEBUG, "get result %s", result);
        if (is_iptables_command_fail(cmd, result) && ++retry < RETRY_MAX_TIME) {
            debug(LOG_DEBUG, "do this command a again");
            sleep(1);
            goto DO_COMMAND;
        }
    }

    if (retry >= RETRY_MAX_TIME) {
        debug(LOG_ERR, "iptables command failed(%d): %s", rc, cmd);
        return -1;
    }

	careful_free(cmd);
	return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg table Table containing the chain.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
	static char *
iptables_compile(const char * table, const char *chain, const t_firewall_rule *rule)
{
	char	command[MAX_BUF],
		*mode;

	memset(command, 0, MAX_BUF);

	switch (rule->target){
	case TARGET_DROP:
		mode = safe_strdup("DROP");
		break;
	case TARGET_REJECT:
		mode = safe_strdup("REJECT");
		break;
	case TARGET_ACCEPT:
		mode = safe_strdup("ACCEPT");
		break;
	case TARGET_LOG:
		mode = safe_strdup("LOG");
		break;
	case TARGET_ULOG:
		mode = safe_strdup("ULOG");
		break;
	}

	snprintf(command, sizeof(command),  "-t %s -A %s ",table, chain);
	if (rule->mask != NULL) {
		snprintf((command + strlen(command)), (sizeof(command) -
					strlen(command)), "-d %s ", rule->mask);
	}
	if (rule->protocol != NULL) {
		snprintf((command + strlen(command)), (sizeof(command) -
					strlen(command)), "-p %s ", rule->protocol);
	}
	if (rule->port != NULL) {
		snprintf((command + strlen(command)), (sizeof(command) -
					strlen(command)), "--dport %s ", rule->port);
	}
	snprintf((command + strlen(command)), (sizeof(command) -
				strlen(command)), "-j %s", mode);

	free(mode);

	/* XXX The buffer command, an automatic variable, will get cleaned
	 * off of the stack when we return, so we strdup() it. */
	return(safe_strdup(command));
}

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
	static void
iptables_load_ruleset(const char * table, const char *ruleset, const char *chain)
{
	t_firewall_rule		*rule;
	char			*cmd;

	debug(LOG_DEBUG, "Load ruleset %s into table %s, chain %s", ruleset, table, chain);

	for (rule = get_ruleset(ruleset); rule != NULL; rule = rule->next) {
		cmd = iptables_compile(table, chain, rule);
		debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
		iptables_do_command(cmd);
		free(cmd);
	}

	debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
}

	void
iptables_fw_clear_authservers(void)
{
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_AUTHSERVERS);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
}

	void
iptables_fw_set_authservers(void)
{
	const s_config *config;
	t_auth_serv *auth_server;

	config = config_get_config();

	for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
		if (auth_server->last_ip && strcmp(auth_server->last_ip, DUMY_IP) != 0) {
			iptables_do_command("-t filter -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
			iptables_do_command("-t nat -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
		}
	}

}

/* cjpthree@126.com 2015.5.13 start */
	void
iptables_fw_clear_appservers(void)
{
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_APPSERVERS);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_APPSERVERS);
}

	void
iptables_fw_set_appservers(void)
{
	const s_config *config;
	t_app_serv *app_server;

	config = config_get_config();

	for (app_server = config->app_servers; app_server != NULL; app_server = app_server->next) {
		if (app_server->last_ip && strcmp(app_server->last_ip, DUMY_IP) != 0) {
			iptables_do_command("-t filter -A " TABLE_WIFIDOG_APPSERVERS " -d %s -j ACCEPT", app_server->last_ip);
			iptables_do_command("-t nat -A " TABLE_WIFIDOG_APPSERVERS " -d %s -j ACCEPT", app_server->last_ip);
		}
	}
}
/* cjpthree@126.com 2015.5.13 end */

/** Initialize the firewall rules
*/
	int
iptables_fw_init(void)
{
	s_config *config;
	char * ext_interface = NULL;
	int gw_port = 0;
	t_trusted_mac *p;
	int proxy_port;
	fw_quiet = 0;
    char *wan_ip;

	LOCK_CONFIG();
	config = config_get_config();
	gw_port = config->gw_port;
    if ((wan_ip = get_iface_ip(config->external_interface)) == NULL) {
		ext_interface = get_ext_iface();
        if (ext_interface && strncasecmp(ext_interface, config->external_interface, strlen(ext_interface) + 1)) {
            careful_free(config->external_interface);
            config->external_interface = safe_strdup(ext_interface);
            (void)uci_set_config("wifidog", "wifidog", "gateway_eninterface", ext_interface);
        }
        if ((wan_ip = get_iface_ip(config->external_interface)) != NULL) {
            careful_free(config->extip);
            config->extip = safe_strdup(wan_ip);
	    }
	} else {
	    careful_free(config->extip);
        config->extip = safe_strdup(wan_ip);
	}
    careful_free(wan_ip);

	/*
	 *
	 * Everything in the MANGLE table
	 *
	 */

	/* Create new chains */
	iptables_do_command("-t mangle -N " TABLE_WIFIDOG_TRUSTED);
	iptables_do_command("-t mangle -N " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t mangle -N " TABLE_WIFIDOG_INCOMING);

	/* Assign links and rules to these new chains */
	iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_OUTGOING, config->gw_interface);
	iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_TRUSTED, config->gw_interface);//this rule will be inserted before the prior one
	iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -j " TABLE_WIFIDOG_INCOMING, config->gw_interface);

    if (config->qosEnable) {
        iptables_do_command("-t mangle -N " TABLE_WIFIDOG_QOS_IN);
        iptables_do_command("-t mangle -N " TABLE_WIFIDOG_QOS_OUT);
        iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_QOS_OUT, config->gw_interface);
        iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -j " TABLE_WIFIDOG_QOS_IN, config->gw_interface);
    }

	for (p = config->trustedmaclist; p != NULL; p = p->next) {
	    (void)client_list_add(p->mac);
        (void)client_list_set_auth(p->mac, CLIENT_CONFIG);
        (void)iptables_fw_allow_mac(p->mac);
        (void)iptables_fw_untracked_mac(p->mac);
	}

	/*
	 *
	 * Everything in the NAT table
	 *
	 */

	/* Create new chains */
	iptables_do_command("-t nat -N " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t nat -N " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	iptables_do_command("-t nat -N " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t nat -N " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t nat -N " TABLE_WIFIDOG_UNKNOWN);
	iptables_do_command("-t nat -N " TABLE_WIFIDOG_AUTHSERVERS);
    //iptables_do_command("-t nat -N " TABLE_WIFIDOG_APPSERVERS);
    iptables_do_command("-t nat -N " TABLE_WIFIDOG_WHITE_URL);

	/* Assign links and rules to these new chains */
	iptables_do_command("-t nat -A PREROUTING -i %s -j " TABLE_WIFIDOG_OUTGOING, config->gw_interface);

	iptables_do_command("-t nat -A " TABLE_WIFIDOG_OUTGOING " -d %s -j " TABLE_WIFIDOG_WIFI_TO_ROUTER, config->gw_address);
	iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_ROUTER " -j ACCEPT");

	iptables_do_command("-t nat -A " TABLE_WIFIDOG_OUTGOING " -j " TABLE_WIFIDOG_WIFI_TO_INTERNET);

    if (config->wd_auth_mode == AUTH_LOCAL_WECHAT) {
        iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -d %s -p tcp --dport 80 -j DNAT --to-destination %s:%u", "10.11.12.13", config->gw_address, config->gw_port);
    }
	if((proxy_port=config_get_config()->proxy_port) != 0){
		debug(LOG_DEBUG,"Proxy port set, setting proxy rule");
		iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_KNOWN, proxy_port);
		iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_PROBATION, proxy_port);
	}

	iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_KNOWN);
	iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_PROBATION);
	iptables_do_command("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_UNKNOWN);

	iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_AUTHSERVERS);
	//iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_APPSERVERS);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_WHITE_URL);
	iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port);


	/*
	 *
	 * Everything in the FILTER table
	 *
	 */

	/* Create new chains */
	iptables_do_command("-t filter -N " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t filter -N " TABLE_WIFIDOG_AUTHSERVERS);
	//iptables_do_command("-t filter -N " TABLE_WIFIDOG_APPSERVERS);
	iptables_do_command("-t filter -N " TABLE_WIFIDOG_WHITE_URL);
	iptables_do_command("-t filter -N " TABLE_WIFIDOG_LOCKED);
	iptables_do_command("-t filter -N " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t filter -N " TABLE_WIFIDOG_VALIDATE);
	iptables_do_command("-t filter -N " TABLE_WIFIDOG_KNOWN);
	iptables_do_command("-t filter -N " TABLE_WIFIDOG_UNKNOWN);

	/* Assign links and rules to these new chains */

	/* Insert at the beginning */
	iptables_do_command("-t filter -I FORWARD -i %s -j " TABLE_WIFIDOG_WIFI_TO_INTERNET, config->gw_interface);


	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m state --state INVALID -j DROP");

	/* XXX: Why this? it means that connections setup after authentication
	   stay open even after the connection is done...
	   iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m state --state RELATED,ESTABLISHED -j ACCEPT");*/

	//Won't this rule NEVER match anyway?!?!? benoitg, 2007-06-23
	//iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -i %s -m state --state NEW -j DROP", ext_interface);

	/* TCPMSS rule for PPPoE */
	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ext_interface);

	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_AUTHSERVERS);
	iptables_fw_set_authservers();
	//iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_APPSERVERS);
	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_WHITE_URL);
    iptables_load_ruleset("filter", "whiteurl", TABLE_WIFIDOG_WHITE_URL);
    iptables_load_ruleset("nat", "whiteurl", TABLE_WIFIDOG_WHITE_URL);

	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j " TABLE_WIFIDOG_LOCKED, FW_MARK_LOCKED);
	iptables_load_ruleset("filter", "locked-users", TABLE_WIFIDOG_LOCKED);

	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_GLOBAL);
	iptables_load_ruleset("filter", "global", TABLE_WIFIDOG_GLOBAL);
	iptables_load_ruleset("nat", "global", TABLE_WIFIDOG_GLOBAL);

	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j " TABLE_WIFIDOG_VALIDATE, FW_MARK_PROBATION);
	iptables_load_ruleset("filter", "validating-users", TABLE_WIFIDOG_VALIDATE);

	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%u -j " TABLE_WIFIDOG_KNOWN, FW_MARK_KNOWN);
	iptables_load_ruleset("filter", "known-users", TABLE_WIFIDOG_KNOWN);

	iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_UNKNOWN);
	iptables_load_ruleset("filter", "unknown-users", TABLE_WIFIDOG_UNKNOWN);
	iptables_do_command("-t filter -A " TABLE_WIFIDOG_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");

	UNLOCK_CONFIG();
    careful_free(ext_interface);
	return 1;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
	int
iptables_fw_destroy(void)
{
	fw_quiet = 1;

	debug(LOG_DEBUG, "Destroying our iptables entries");

	/*
	 *
	 * Everything in the MANGLE table
	 *
	 */
	debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
	iptables_fw_destroy_mention("mangle", "PREROUTING", TABLE_WIFIDOG_TRUSTED);
	iptables_fw_destroy_mention("mangle", "PREROUTING", TABLE_WIFIDOG_OUTGOING);
	iptables_fw_destroy_mention("mangle", "POSTROUTING", TABLE_WIFIDOG_INCOMING);
	iptables_do_command("-t mangle -F " TABLE_WIFIDOG_TRUSTED);
	iptables_do_command("-t mangle -F " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t mangle -F " TABLE_WIFIDOG_INCOMING);
	iptables_do_command("-t mangle -X " TABLE_WIFIDOG_TRUSTED);
	iptables_do_command("-t mangle -X " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t mangle -X " TABLE_WIFIDOG_INCOMING);

	/*
	 *
	 * Everything in the NAT table
	 *
	 */
	debug(LOG_DEBUG, "Destroying chains in the NAT table");
	iptables_fw_destroy_mention("nat", "PREROUTING", TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
	//iptables_do_command("-t nat -F " TABLE_WIFIDOG_APPSERVERS);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_WHITE_URL);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_UNKNOWN);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_AUTHSERVERS);
	//iptables_do_command("-t nat -X " TABLE_WIFIDOG_APPSERVERS);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_WHITE_URL);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_UNKNOWN);

	/*
	 *
	 * Everything in the FILTER table
	 *
	 */
	debug(LOG_DEBUG, "Destroying chains in the FILTER table");
	iptables_fw_destroy_mention("filter", "FORWARD", TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_AUTHSERVERS);
	//iptables_do_command("-t filter -F " TABLE_WIFIDOG_APPSERVERS);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_WHITE_URL);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_LOCKED);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_VALIDATE);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_KNOWN);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_UNKNOWN);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_AUTHSERVERS);
	//iptables_do_command("-t filter -X " TABLE_WIFIDOG_APPSERVERS);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_WHITE_URL);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_LOCKED);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_VALIDATE);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_KNOWN);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_UNKNOWN);

    if (config_get_config()->qosEnable) {
        iptables_fw_destroy_mention("mangle", "POSTROUTING", TABLE_WIFIDOG_QOS_IN);
        iptables_fw_destroy_mention("mangle", "PREROUTING", TABLE_WIFIDOG_QOS_OUT);
        iptables_do_command("-t mangle -F " TABLE_WIFIDOG_QOS_IN);
        iptables_do_command("-t mangle -F " TABLE_WIFIDOG_QOS_OUT);
        iptables_do_command("-t mangle -X " TABLE_WIFIDOG_QOS_IN);
        iptables_do_command("-t mangle -X " TABLE_WIFIDOG_QOS_OUT);
    }

	return 1;
}

/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
int
iptables_fw_destroy_mention(
		const char * table,
		const char * chain,
		const char * mention
		) {
	FILE *p = NULL;
	char *command;
	char command2[ONE_COMAND_MAX_LENGTH] = {0};
	char line[MAX_BUF] = {0};
	char rulenum[10] = {0};
	char *victim;
	int deleted = 0;

    victim = safe_strdup(mention);
    command = (char *)safe_malloc(ONE_COMAND_MAX_LENGTH);

	iptables_insert_gateway_id(&victim);

	debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", victim, table, chain);

#if IPTABELES_VESION > (1421)
	sprintf(command, "iptables -t %s -L %s -n --line-numbers -v -w", table, chain);
#else
    sprintf(command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
#endif
	iptables_insert_gateway_id(&command);

    char result[POPEN_MAX_BUF];
    char *analyze;
    int rc;
    int i;

    memset(result, 0, POPEN_MAX_BUF);
    rc = execute_cmd(command, result);
    if (rc != 0) {
        debug(LOG_ERR, "run command %s failed", command);
        careful_free(victim);
        careful_free(command);
        return -1;
    }

    result[POPEN_MAX_BUF - 1] = '\0';
    analyze = result;
	if (analyze && strlen(analyze)) {
        //debug(LOG_DEBUG, "get result %s", analyze);
		/* Skip first 2 lines */
        for (i = 0; analyze - result < POPEN_MAX_BUF && i < 2; i++) {
            if (strlen(analyze)) {
                analyze = strstr(analyze, "\n");
                if (!analyze) {
                    careful_free(victim);
                    careful_free(command);
                    return -1;      /* fixbug: result fill POPEN_MAX_BUF */
                }
                while (*++analyze == '\n');
            }
            //debug(LOG_DEBUG, "analyze - result: %ld, analyze: \n%s", analyze - result, analyze);
        }
		/* Loop over entries */
        while (strlen(analyze)) {
    		memcpy(line, analyze, MAX_BUF);
            analyze += MAX_BUF;
            //debug(LOG_DEBUG, "3 line %s", line);
    		/* Look for victim */
    		if (strstr(line, victim)) {
                 //debug(LOG_DEBUG, "line \n%s", line);
    			/* Found victim - Get the rule number into rulenum */
    			if (sscanf(line, "%9[0-9]", rulenum) == 1) {
    				/* Delete the rule: */
    				debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain, victim);
    				sprintf(command2, "-t %s -D %s %s", table, chain, rulenum);
                    //debug(LOG_DEBUG, "4");
                    debug(LOG_DEBUG, "doing command: iptables %s", command2);
                    iptables_do_command(command2);
                    //debug(LOG_DEBUG, "doing command iptables %s", command2);
    				deleted = 1;
                    break;
    			}
    		}
        }
	}

    careful_free(victim);
    careful_free(command);

	if (deleted) {
		/* Recurse just in case there are more in the same table+chain */
		iptables_fw_destroy_mention(table, chain, mention);
	}

	return (deleted);
}

/** Set if a specific client has access through the firewall */
	int
iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
	int rc = 0;

	fw_quiet = 0;

	switch(type) {
		case FW_ACCESS_ALLOW:
			iptables_do_command("-t mangle -A " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", mac, tag);
			rc = iptables_do_command("-t mangle -A " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
			break;
		case FW_ACCESS_DENY:
			iptables_do_command("-t mangle -D " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", mac, tag);
			rc = iptables_do_command("-t mangle -D " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}

static pthread_mutex_t fw_allow_mac_mutex = PTHREAD_MUTEX_INITIALIZER;
int iptables_fw_allow_mac(const char *mac)
{
	int rc = 0;
    client_t client;

#if _CHECK_CAREFUL_
    if (!is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&fw_allow_mac_mutex);
    if (client_list_get_client(mac, &client)) {
        pthread_mutex_unlock(&fw_allow_mac_mutex);
        return -1;
    }

    if (CLIENT_ALLOWED == client.fw_state) {
        pthread_mutex_unlock(&fw_allow_mac_mutex);
        return 0;
    }

    rc = iptables_do_command("-t mangle -A " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", mac, FW_MARK_KNOWN);
    if (rc) {
        pthread_mutex_unlock(&fw_allow_mac_mutex);
        return rc;
    }
    if (client_list_set_fw_state(mac, CLIENT_ALLOWED)) {
        pthread_mutex_unlock(&fw_allow_mac_mutex);
        return -1;
    }
    (void)client_list_set_allow_time(mac, time(NULL));
    pthread_mutex_unlock(&fw_allow_mac_mutex);

	return rc;
}

int iptables_fw_deny_mac(const char *mac)
{
	int rc = 0;
    client_t client;

#if _CHECK_CAREFUL_
    if (!is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&fw_allow_mac_mutex);
    if (client_list_get_client(mac, &client)) {
        pthread_mutex_unlock(&fw_allow_mac_mutex);
        return -1;
    }

    if (CLIENT_DENIED == client.fw_state) {
        pthread_mutex_unlock(&fw_allow_mac_mutex);
        return 0;
    }

    (void)iptables_do_command("-t mangle -D " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", mac, FW_MARK_KNOWN);

    if (client_list_set_fw_state(mac, CLIENT_DENIED)) {
        pthread_mutex_unlock(&fw_allow_mac_mutex);
        return -1;
    }
    //(void)client_list_set_allow_time(mac, 0);
    pthread_mutex_unlock(&fw_allow_mac_mutex);

	return rc;
}

static pthread_mutex_t fw_tracked_mac_mutex = PTHREAD_MUTEX_INITIALIZER;
int iptables_fw_tracked_mac(const char *mac)
{
	int rc = 0;
    client_t client;
    client_t old_client;
    char *rarp_ip = NULL;
    char find_mac[MAC_ADDR_LEN] = {0};

#if _CHECK_CAREFUL_
    if (!is_mac_valid(mac)) {
        return -1;
    }
#endif
    debug(LOG_INFO, "mac %s", mac);

    pthread_mutex_lock(&fw_tracked_mac_mutex);
    if (client_list_get_client(mac, &client)) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        return -1;
    }

    if (CLIENT_TRACKED == client.tracked) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        return 0;
    }

    rarp_ip = rarp_get(mac);
    if (!is_ip_valid(rarp_ip)) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        careful_free(rarp_ip);
        return -1;
    }
    debug(LOG_INFO, "rarp_ip %s", rarp_ip);

    if (!client_list_find_mac_by_ip_exclude(rarp_ip, mac, find_mac)) {
        debug(LOG_INFO, "find_mac %s", find_mac);
        /* DHCP have given this ip to a new client */
        if (strncasecmp(mac, find_mac, MAC_ADDR_LEN)) {
            (void)client_list_set_tracked(find_mac, CLIENT_UNTRACKED);
            (void)iptables_do_command("-t mangle -D " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", rarp_ip);
            if (tracked_clients_num) {
                tracked_clients_num--;
            }
            (void)client_list_set_ip(find_mac, DUMY_IP);
        }
    }

    (void)client_list_set_ip(mac, rarp_ip);
    memset(client.ip, 0, MAX_IPV4_LEN);
    memcpy(client.ip, rarp_ip, strlen(rarp_ip) + 1);
    careful_free(rarp_ip);

    rc = iptables_do_command("-t mangle -A " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", client.ip);
    if (rc) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        return rc;
    }
    tracked_clients_num++;
    if (client_list_set_tracked(mac, CLIENT_TRACKED)) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        return -1;
    }
    pthread_mutex_unlock(&fw_tracked_mac_mutex);

	return rc;
}

int iptables_fw_untracked_mac(const char *mac)
{
	int rc = 0;
    client_t client;


#if _CHECK_CAREFUL_
    if (!is_mac_valid(mac)) {
        return -1;
    }
#endif

    pthread_mutex_lock(&fw_tracked_mac_mutex);
    if (client_list_get_client(mac, &client)) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        return -1;
    }

    if (CLIENT_UNTRACKED == client.tracked) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        return 0;
    }

    if (!is_ip_valid(client.ip) || !strncmp(client.ip, DUMY_IP, strlen(DUMY_IP) + 1)) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        return -1;
    }

    (void)iptables_do_command("-t mangle -D " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", client.ip);

    if (tracked_clients_num) {
        tracked_clients_num--;
    }
    if (client_list_set_tracked(mac, CLIENT_UNTRACKED)) {
        pthread_mutex_unlock(&fw_tracked_mac_mutex);
        return -1;
    }
    pthread_mutex_unlock(&fw_tracked_mac_mutex);

	return rc;
}

#define MAX_ICMP_BYTES (48UL)
int iptables_fw_counters_update_incoming(void)
{
	char *script,
	     ip[MAX_IPV4_LEN],
	     mac[MAC_ADDR_LEN],
	     rc;
    unsigned long long int counter;
	client_t client;
    time_t current_time = time(NULL);

#if IPTABELES_VESION > (1421)
	safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_INCOMING " -w");
#else
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_INCOMING);
#endif

	iptables_insert_gateway_id(&script);

    char result[POPEN_MAX_BUF];
    char *analyze;
    int i;

    memset(result, 0, POPEN_MAX_BUF);
    rc = execute_cmd(script, result);
    if (rc != 0) {
        debug(LOG_ERR, "run command %s failed\n", script);
        return rc;
    }

    result[POPEN_MAX_BUF - 1] = '\0';
    analyze = result;
	if (analyze && strlen(analyze)) {
        //debug(LOG_DEBUG, "get result :\n%s", analyze);
		/* Skip first 2 lines */
        for (i = 0; analyze - result < POPEN_MAX_BUF && i < 2; i++) {
            if (strlen(analyze)) {
                analyze = strstr(analyze, "\n");
                if (!analyze) {
                    return -1;      /* fixbug: result fill POPEN_MAX_BUF */
                }
                while (*++analyze == '\n');
            }
            //debug(LOG_DEBUG, "analyze - result: %ld, analyze:\n%s", analyze - result, analyze);
        }
		/* Loop over entries */
        while (strlen(analyze)) {
            rc = sscanf(analyze, "%*s %llu %*s %*s %*s %*s %*s %*s %15[0-9.]", &counter, ip);
    		if (2 == rc) {
    			/* Sanity */
    			if (!is_ip_valid(ip)) {
    				debug(LOG_WARNING, "I was supposed to read an Ip address but instead got [%s] - ignoring it", ip);
                    goto NEXT_LINE;
    			}
                memset(mac, 0, MAC_ADDR_LEN);
                if (client_list_find_mac_by_ip(ip, mac)) {
                    goto NEXT_LINE;
    		    }
    			debug(LOG_DEBUG, "Read INCOMING traffic for %s: Bytes=%llu", ip, counter);
                if(client_list_get_client(mac, &client)) {
                    debug(LOG_WARNING, "fail to client_list_get_client for %s", mac);
                    goto NEXT_LINE;
                }

                if (client.counters.incoming != counter) {
#if 0
                    if (abs(client.counters.incoming - counter) <= MAX_ICMP_BYTES) {
                        if (current_time - client.counters.last_updated
                            > (config_get_config()->clienttimeout / 2) * config_get_config()->checkinterval) {
                            char *real_ip = NULL;
                            real_ip = rarp_get(mac);
                            if (is_ip_valid(real_ip)) {
                                (void)client_list_set_incoming(mac, counter);
                                (void)client_list_set_last_updated(mac, current_time);
                                debug(LOG_DEBUG, "%s - Updated incoming to %llu bytes.  Updated last_updated to %d",
                                    mac, counter, current_time);
                            }
                        }
                        goto NEXT_LINE;
                    }
#endif
                    (void)client_list_set_incoming(mac, counter);
                    (void)client_list_set_last_updated(mac, current_time);
                    debug(LOG_DEBUG, "%s - Updated incoming to %llu bytes.  Updated last_updated to %d",
                        mac, counter, current_time);
                }
    		}

NEXT_LINE:
            if (strlen(analyze)) {
                analyze = strstr(analyze, "\n");
                if (!analyze) {
                    break;      /* fixbug: result fill POPEN_MAX_BUF */
                }
                while (*++analyze == '\n');
            }
        }
    }

	return 1;
}

int iptables_fw_counters_update_outgoing(void)
{
	char *script,
	     mac[MAC_ADDR_LEN],
	     rc;
	unsigned long long int counter;
    unsigned long long outgoing;

	/* Look for outgoing traffic */
#if IPTABELES_VESION > (1421)
	safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_TRUSTED " -w");
#else
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_TRUSTED);
#endif
	iptables_insert_gateway_id(&script);

    char result[POPEN_MAX_BUF];
    char *analyze;
    int i;

    memset(result, 0, POPEN_MAX_BUF);
    rc = execute_cmd(script, result);
    if (rc != 0) {
        debug(LOG_ERR, "run command %s failed\n", script);
        return rc;
    }

    result[POPEN_MAX_BUF - 1] = '\0';
    analyze = result;
	if (analyze && strlen(analyze)) {
        //debug(LOG_DEBUG, "get result :\n%s", analyze);
		/* Skip first 2 lines */
        for (i = 0; analyze - result < POPEN_MAX_BUF && i < 2; i++) {
            if (strlen(analyze)) {
                analyze = strstr(analyze, "\n");
                if (!analyze) {
                    return -1;      /* fixbug: result fill POPEN_MAX_BUF */
                }
                while (*++analyze == '\n');
            }
            //debug(LOG_DEBUG, "analyze - result: %ld, analyze:\n%s", analyze - result, analyze);
        }
		/* Loop over entries */
        while (strlen(analyze)) {
            rc = sscanf(analyze, "%*s %llu %*s %*s %*s %*s %*s %*s %*s %*s %17[0-9a-fA-F:] %*s %*s %*s", &counter, mac);
    		if (2 == rc) {
    			/* Sanity */
    			if (!is_mac_valid(mac)) {
    				debug(LOG_WARNING, "I was supposed to read an Mac address but instead got [%s] - ignoring it", mac);
                    goto NEXT_LINE;
    			}
    			debug(LOG_DEBUG, "Read TRUSTED traffic for %s: Bytes=%llu", mac, counter);
                if(client_list_get_outgoing(mac, &outgoing)) {
                    debug(LOG_WARNING, "fail to client_list_get_outgoing for %s", mac);
                    goto NEXT_LINE;
                }

                if (outgoing != counter) {
                    time_t current_time = time(NULL);
                    (void)client_list_set_outgoing(mac, counter);
                    (void)client_list_set_last_updated(mac, current_time);
                    debug(LOG_DEBUG, "%s - Updated and outgoing to %llu bytes.  Updated last_updated to %d",
                        mac, counter, current_time);
                }
    		}

NEXT_LINE:
            if (strlen(analyze)) {
                analyze = strstr(analyze, "\n");
                if (!analyze) {
                    break;      /* fixbug: result fill POPEN_MAX_BUF */
                }
                while (*++analyze == '\n');
            }
        }
    }

	return 1;
}

int iptables_fw_counters_update(void)
{
    int ret;

    if (-1 == iptables_fw_counters_update_incoming()) {
        return -1;
    }

	if (-1 == iptables_fw_counters_update_outgoing()) {
        return -1;
	}

	return 0;
}


