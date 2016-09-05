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
/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire, Technologies Coeus inc.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>

#include <string.h>
#include <ctype.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"

#include "util.h"
#include "watchdog.h"

/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oExternalInterface,
	oGatewayID,
	oGatewayInterface,
	oGatewayAddress,
	oGatewayPort,
	oAuthServer,
	oAppServer, /* cjpthree@126.com 2015.5.13 */
	oAuthServHostname,
	oAuthServSSLAvailable,
	oAuthServSSLPort,
	oAuthServHTTPPort,
	oAuthServPath,
    oAppServHost, /* cjpthree@126.com 2015.5.13 */
    oAppServPort, /* cjpthree@126.com 2015.5.13 */
    oAppServPath, /* cjpthree@126.com 2015.5.13 */
	oAuthServLoginScriptPathFragment,
	oAuthServPortalScriptPathFragment,
	oAuthServMsgScriptPathFragment,
	oAuthServPingScriptPathFragment,
	oAuthServAuthScriptPathFragment,
	oAuthServUpdateScriptPathFragment,//add jore
	oAuthServDownloadScriptPathFragment,//add jore
	oAuthServConfigScriptPathFragment,//add jore
    oAuthServAuthMacScriptPathFragment, /* cjpthree@126.com 2015.6.26 */
    oAppServGetAddressPathFragment, /* cjpthree@126.com 2015.5.7 */
	oHTTPDMaxConn,
	oHTTPDName,
	oHTTPDRealm,
    oHTTPDUsername,
    oHTTPDPassword,
	oClientTimeout,
	oCheckInterval,
	oThreadWatchdogTimeout,
	oAutoSsid,
	oAutoPassword,
	oAuto_wireless_pw,
    oQos_enable,
    oUplink_vip,
    oDownlink_vip,
    oUplink_common,
    oDownlink_common,
	oWdctlSocket,
	oSyslogFacility,
	oFirewallRule,
	oFirewallRuleSet,
	oTrustedMACList,
    oHtmlMessageFile,
	oProxyPort,
	owd_auth_mode,
	owd_wechat_forceAttention,
	owd_wechat_officialAccount,
	owd_wechat_shopId,
	owd_wechat_appId,
	owd_wechat_secretKey,
	owd_wechat_extend,
	owd_to_url,
	owd_skip_SuccessPage,
	owd_reAssoc_reAuth,
	oaudit_enable,
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
} keywords[] = {
	{ "daemon",             	oDaemon },
	{ "debuglevel",         	oDebugLevel },
	{ "externalinterface",  	oExternalInterface },
	{ "gatewayid",          	oGatewayID },
	{ "gatewayinterface",   	oGatewayInterface },
	{ "gatewayaddress",     	oGatewayAddress },
	{ "gatewayport",        	oGatewayPort },
	{ "authserver",         	oAuthServer },
    { "appserver",              oAppServer }, /* cjpthree@126.com 2015.5.13 */
	{ "httpdmaxconn",       	oHTTPDMaxConn },
	{ "httpdname",          	oHTTPDName },
	{ "httpdrealm",			oHTTPDRealm },
	{ "httpdusername",		oHTTPDUsername },
	{ "httpdpassword",		oHTTPDPassword },
	{ "clienttimeout",      	oClientTimeout },
	{ "checkinterval",      	oCheckInterval },
	{ "Thread_watchdog_timeout", oThreadWatchdogTimeout },
    { "Auto_ssid", oAutoSsid},
    { "Auto_password", oAutoPassword},
    { "Auto_ssid",              oAutoSsid },
    { "Auto_password",          oAutoPassword },
    { "Auto_wireless_pw",       oAuto_wireless_pw },
    { "Qos_enable",             oQos_enable },
    { "Uplink_vip",             oUplink_vip },
    { "Downlink_vip",           oDownlink_vip },
    { "Uplink_common",          oUplink_common },
    { "Downlink_common",        oDownlink_common },
	{ "syslogfacility", 		oSyslogFacility },
	{ "wdctlsocket",		oWdctlSocket },
	{ "hostname",			oAuthServHostname },
	{ "sslavailable",		oAuthServSSLAvailable },
	{ "sslport",			oAuthServSSLPort },
	{ "httpport",			oAuthServHTTPPort },
	{ "path",			oAuthServPath },
    { "appservhost",    oAppServHost }, /* cjpthree@126.com 2015.5.13 */
    { "appservport",    oAppServPort }, /* cjpthree@126.com 2015.5.13 */
    { "appservpath",    oAppServPath }, /* cjpthree@126.com 2015.5.7 */
	{ "loginscriptpathfragment",	oAuthServLoginScriptPathFragment },
	{ "portalscriptpathfragment",	oAuthServPortalScriptPathFragment },
	{ "msgscriptpathfragment",	oAuthServMsgScriptPathFragment },
	{ "pingscriptpathfragment",	oAuthServPingScriptPathFragment },
	{ "authscriptpathfragment",	oAuthServAuthScriptPathFragment },
	{ "updatescriptpathfragment",	oAuthServUpdateScriptPathFragment },//add jore
	{ "downloadscriptpathfragment",	oAuthServDownloadScriptPathFragment },//add jore
	{ "configscriptpathfragment",	oAuthServConfigScriptPathFragment },//add jore
    { "authmacscriptpathfragment",	oAuthServAuthMacScriptPathFragment }, /* cjpthree@126.com 2015.6.26 */
    { "getaddresspathfragment", oAppServGetAddressPathFragment }, /* cjpthree@126.com 2015.5.7 */
	{ "firewallruleset",		oFirewallRuleSet },
	{ "firewallrule",		oFirewallRule },
	{ "trustedmaclist",		oTrustedMACList },
    { "htmlmessagefile",		oHtmlMessageFile },
	{ "proxyport",			oProxyPort },
	{ "Wd_auth_mode",		owd_auth_mode },
	{ "Wd_skip_SuccessPage",		owd_skip_SuccessPage },
	{ "Wd_reAssoc_reAuth",		owd_reAssoc_reAuth },
	{ "Wd_wechat_forceAttention",   owd_wechat_forceAttention },
	{ "Wd_wechat_officialAccount",   owd_wechat_officialAccount },
	{ "Wd_wechat_shopId",   owd_wechat_shopId },
	{ "Wd_wechat_appId",    owd_wechat_appId },
	{ "Wd_wechat_secretKey", owd_wechat_secretKey },
	{ "Wd_wechat_extend",   owd_wechat_extend },
	{ "wd_to_url",	owd_to_url },
	{ "audit_enable", oaudit_enable },
	{ NULL,				oBadOption },
};

static void config_notnull(const void *parm, const char *parmname);
static int parse_boolean_value(char *);
static void parse_auth_server(FILE *, const char *, int *);
static void parse_app_server(FILE *file, const char *filename, int *linenum); /* cjpthree@126.com 2015.5.13 */
static int _parse_firewall_rule(const char *ruleset, char *leftover);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);

static OpCodes config_parse_token(const char *cp, const char *filename, int linenum);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
inline s_config *
config_get_config(void)
{
    return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
    memset(&config, 0, sizeof(config));
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile));
	config.htmlmsgfile = safe_strdup(DEFAULT_HTMLMSGFILE);
	config.debuglevel = DEFAULT_DEBUGLEVEL;
	config.httpdmaxconn = DEFAULT_HTTPDMAXCONN;
	config.external_interface = safe_strdup(DEFAULT_EXTERNAL_INTERFACE);
	config.gw_id = DEFAULT_GATEWAYID;
	config.gw_interface = NULL;
	config.gw_address = NULL;
	config.gw_port = DEFAULT_GATEWAYPORT;
	config.auth_servers = NULL;
	config.httpdname = NULL;
	config.httpdrealm = DEFAULT_HTTPDNAME;
	config.httpdusername = NULL;
	config.httpdpassword = NULL;
	config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
    config.autoSsid = DEFAULT_AUTO_SSID;
    config.autoPassword = DEFAULT_AUTO_PASSWORD;
    config.autoWirelessPw = DEFAULT_AUTOWIRELESSPW;
    config.qosEnable = DEFAULT_QOSENABLE;
    config.uplinkVip = DEFAULT_UPLINKVIP;
    config.downlinkVip = DEFAULT_DOWNLINKVIP;
    config.uplinkCommon = DEFAULT_UPLINKCOMMON;
    config.downlinkCommon = DEFAULT_DOWNLINKCOMMON;
    config.threadWatchdogTimeout = DEF_THREAD_WATCHDOG_TIMEOUT;
	config.checkinterval = DEFAULT_CHECKINTERVAL;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	config.daemon = -1;
	config.log_syslog = DEFAULT_LOG_SYSLOG;
	config.wdctl_sock = safe_strdup(DEFAULT_WDCTL_SOCK);
	config.internal_sock = safe_strdup(DEFAULT_INTERNAL_SOCK);
	config.rulesets = NULL;
	config.trustedmaclist = NULL;
	config.proxy_port = 0;
	config.wd_auth_mode = 0;
    config.wd_wechat_forceAttention = 0;
    //config.wd_wechat_officialAccount = NULL;
    config.wd_wechat_shopId = NULL;
    config.wd_wechat_appId = NULL;
    config.wd_wechat_secretKey = NULL;
    config.wd_wechat_extend = NULL;
    config.wd_to_url = NULL;
    config.wd_skip_SuccessPage = 0;
    config.wd_reAssoc_reAuth = 0;
    config.audit_enable = 0;
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void
config_init_override(void)
{
    if (config.daemon == -1) config.daemon = DEFAULT_DAEMON;
}

/** @internal
Parses a single token from the config file
*/
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s",
			filename, linenum, cp);
	return oBadOption;
}


/** @internal
Parses auth server information
*/
static void
parse_auth_server(FILE *file, const char *filename, int *linenum)
{
	char		*host = NULL,
			*path = NULL,
			*loginscriptpathfragment = NULL,
			*portalscriptpathfragment = NULL,
			*msgscriptpathfragment = NULL,
			*pingscriptpathfragment = NULL,
			*authscriptpathfragment = NULL,
			*updatescriptpathfragment = NULL,//add jore
			*downloadscriptpathfragment = NULL,//add jore
			*configscriptpathfragment = NULL,//add jore
            *authmacscriptpathfragment = NULL, /* cjpthree@126.com 2015.6.26 */
			line[MAX_BUF],
			*p1,
			*p2;
	int		http_port,
			ssl_port,
			ssl_available,
			opcode;
	t_auth_serv	*new,
			*tmp;

	/* Defaults */
	path = safe_strdup(DEFAULT_AUTHSERVPATH);
	loginscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
	portalscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
	msgscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
	pingscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
	authscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
	updatescriptpathfragment = safe_strdup(DEFAULT_AUTHSERVUPDATEPATHFRAGMENT);//add jore
	downloadscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVDOWNLOADPATHFRAGMENT);//add jore
	configscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVCONFIGPATHFRAGMENT);//add jore
    authmacscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVAUTHMACPATHFRAGMENT); /* cjpthree@126.com 2015.6.26 */
	http_port = DEFAULT_AUTHSERVPORT;
	ssl_port = DEFAULT_AUTHSERVSSLPORT;
	ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;


	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++; /* increment line counter. */

		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;

			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);

			switch (opcode) {
				case oAuthServHostname:
					host = safe_strdup(p2);
					break;
				case oAuthServPath:
					free(path);
					path = safe_strdup(p2);
					break;
				case oAuthServLoginScriptPathFragment:
					free(loginscriptpathfragment);
					loginscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServPortalScriptPathFragment:
					free(portalscriptpathfragment);
					portalscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServMsgScriptPathFragment:
					free(msgscriptpathfragment);
					msgscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServPingScriptPathFragment:
					free(pingscriptpathfragment);
					pingscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServAuthScriptPathFragment:
					free(authscriptpathfragment);
					authscriptpathfragment = safe_strdup(p2);
					break;
                    /*add jore*/
				case oAuthServUpdateScriptPathFragment:
					free(updatescriptpathfragment);
					updatescriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServDownloadScriptPathFragment:
					free(downloadscriptpathfragment);
					downloadscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServConfigScriptPathFragment:
					free(configscriptpathfragment);
					configscriptpathfragment = safe_strdup(p2);
					break;
                    /*add jore end */
                case oAuthServAuthMacScriptPathFragment: /* cjpthree@126.com 2015.6.26 */
                    free(authmacscriptpathfragment);
					authmacscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServSSLPort:
					ssl_port = atoi(p2);
                    if (!ssl_port) {
                        debug(LOG_ERR, "ssl_port can not be 0");
                        ssl_port = DEFAULT_AUTHSERVSSLPORT;
                    }
					break;
				case oAuthServHTTPPort:
					http_port = atoi(p2);
                    if (!http_port) {
                        debug(LOG_ERR, "http_port can not be 0");
                        http_port = DEFAULT_AUTHSERVPORT;
                    }
					break;
				case oAuthServSSLAvailable:
					ssl_available = parse_boolean_value(p2);
					if (ssl_available < 0)
						ssl_available = 0;
					break;
				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}
	}

	/* only proceed if we have an host and a path */
	if (host == NULL)
		return;

	debug(LOG_DEBUG, "Adding %s:%d (SSL: %d) %s to the auth server list",
			host, http_port, ssl_port, path);

	/* Allocate memory */
	new = safe_malloc(sizeof(t_auth_serv));

	/* Fill in struct */
	memset(new, 0, sizeof(t_auth_serv)); /*< Fill all with NULL */
	new->authserv_hostname = host;
	new->authserv_use_ssl = ssl_available;
	new->authserv_path = path;
	new->authserv_login_script_path_fragment = loginscriptpathfragment;
	new->authserv_portal_script_path_fragment = portalscriptpathfragment;
	new->authserv_msg_script_path_fragment = msgscriptpathfragment;
	new->authserv_ping_script_path_fragment = pingscriptpathfragment;
	new->authserv_auth_script_path_fragment = authscriptpathfragment;
	new->authserv_update_script_path_fragment = updatescriptpathfragment;//add jore
	new->authserv_download_script_path_fragment = downloadscriptpathfragment;//add jore
	new->authserv_config_script_path_fragment = configscriptpathfragment;//add jore
    new->authserv_authmac_script_path_fragment = authmacscriptpathfragment; /* cjpthree@126.com 2015.6.26 */
	new->authserv_http_port = http_port;
	new->authserv_ssl_port = ssl_port;

	/* If it's the first, add to config, else append to last server */
	if (config.auth_servers == NULL) {
		config.auth_servers = new;
	} else {
		for (tmp = config.auth_servers; tmp->next != NULL;
				tmp = tmp->next);
		tmp->next = new;
	}

	debug(LOG_DEBUG, "Auth server added");
}


/** @internal
Parses app server information
cjpthree@126.com 2015.5.13
*/
static void
parse_app_server(FILE *file, const char *filename, int *linenum)
{
	char	*host = NULL,
			*appserv_path = NULL,
            *getaddresspathfragment = NULL,
			line[MAX_BUF],
			*p1,
			*p2;
	int		http_port,
			opcode;
	t_app_serv	*new,
			*tmp;

	/* Defaults */
    appserv_path = safe_strdup(DEFAULT_APPSERVPATH);
    getaddresspathfragment = safe_strdup(DEFAULT_APPSERVERVGETADDRESSFRAGMENT);

	http_port = DEFAULT_APPSERVPORT;

	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++; /* increment line counter. */

		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;

			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);

			switch (opcode) {
				case oAppServHost:
					host = safe_strdup(p2);
					break;
                case oAppServPath:
                    free(appserv_path);
                    appserv_path = safe_strdup(p2);
                    break;
                case oAppServGetAddressPathFragment:
                    free(getaddresspathfragment);
                    getaddresspathfragment = safe_strdup(p2);
                    break;
				case oAppServPort:
					http_port = atoi(p2);
					break;
				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}
	}

	/* only proceed if we have an host and a path */
	if (host == NULL) {
        debug(LOG_ERR, "Host can not be null");
		return;
	}

	debug(LOG_DEBUG, "Adding %s:%d:%s to the app server list",
			host, http_port, appserv_path);

	/* Allocate memory */
	new = safe_malloc(sizeof(t_app_serv));

	/* Fill in struct */
	memset(new, 0, sizeof(t_app_serv)); /*< Fill all with NULL */
	new->appserv_hostname= host;
	new->appserv_path= appserv_path;
    new->appserv_get_address_path_fragment = getaddresspathfragment;
	new->appserv_http_port= http_port;

	/* If it's the first, add to config, else append to last server */
	if (config.app_servers == NULL) {
		config.app_servers = new;
	} else {
		for (tmp = config.app_servers; tmp->next != NULL; tmp = tmp->next);
		tmp->next = new;
	}

	debug(LOG_DEBUG, "App server added");
}


/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** @internal
Parses firewall rule set information
*/
static void
parse_firewall_ruleset(const char *ruleset, FILE *file, const char *filename, int *linenum)
{
	char		line[MAX_BUF],
			*p1,
			*p2;
	int		opcode;

	debug(LOG_DEBUG, "Adding Firewall Rule Set %s", ruleset);

	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++; /* increment line counter. */

		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;

			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);

			debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);

			switch (opcode) {
				case oFirewallRule:
					_parse_firewall_rule(ruleset, p2);
					break;

				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}
	}

	debug(LOG_DEBUG, "Firewall Rule Set %s added.", ruleset);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static int
_parse_firewall_rule(const char *ruleset, char *leftover)
{
	int i;
	t_firewall_target target = TARGET_REJECT; /**< firewall target */
	int all_nums = 1; /**< If 0, port contained non-numerics */
	int finished = 0; /**< reached end of line */
	char *token = NULL; /**< First word */
	char *port = NULL; /**< port to open/block */
	char *protocol = NULL; /**< protocol to block, tcp/udp/icmp */
	char *mask = NULL; /**< Netmask */
	char *other_kw = NULL; /**< other key word */
	t_firewall_ruleset *tmpr;
	t_firewall_ruleset *tmpr2;
	t_firewall_rule *tmp;
	t_firewall_rule *tmp2;

	debug(LOG_DEBUG, "leftover: %s", leftover);

	/* lower case */
	for (i = 0; *(leftover + i) != '\0'
			&& (*(leftover + i) = tolower((unsigned char)*(leftover + i))); i++);

	token = leftover;
	TO_NEXT_WORD(leftover, finished);

	/* Parse token */
	if (!strcasecmp(token, "block") || finished) {
		target = TARGET_REJECT;
	} else if (!strcasecmp(token, "drop")) {
		target = TARGET_DROP;
	} else if (!strcasecmp(token, "allow")) {
		target = TARGET_ACCEPT;
	} else if (!strcasecmp(token, "log")) {
		target = TARGET_LOG;
	} else if (!strcasecmp(token, "ulog")) {
		target = TARGET_ULOG;
	} else {
		debug(LOG_ERR, "Invalid rule type %s, expecting "
				"\"block\",\"drop\",\"allow\",\"log\" or \"ulog\"", token);
		return -1;
	}

	/* Parse the remainder */
	/* Get the protocol */
	if (strncmp(leftover, "tcp", 3) == 0
			|| strncmp(leftover, "udp", 3) == 0
			|| strncmp(leftover, "icmp", 4) == 0) {
		protocol = leftover;
		TO_NEXT_WORD(leftover, finished);
	}

	/* should be exactly "port" */
	if (strncmp(leftover, "port", 4) == 0) {
		TO_NEXT_WORD(leftover, finished);
		/* Get port now */
		port = leftover;
		TO_NEXT_WORD(leftover, finished);
		for (i = 0; *(port + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(port + i)))
				//all_nums = 0; /*< No longer only digits */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid port %s", port);
			return -3; /*< Fail */
		}
	}

	/* Now, further stuff is optional */
	if (!finished) {
		/* should be exactly "to" */
		other_kw = leftover;
		TO_NEXT_WORD(leftover, finished);
		if (strcmp(other_kw, "to") || finished) {
			debug(LOG_ERR, "Invalid or unexpected keyword %s, "
					"expecting \"to\"", other_kw);
			return -4; /*< Fail */
		}

		/* Get port now */
		mask = leftover;
		TO_NEXT_WORD(leftover, finished);
		all_nums = 1;
		for (i = 0; *(mask + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(mask + i)) && (*(mask + i) != '.')
					&& (*(mask + i) != '/'))
				//all_nums = 0; /*< No longer only digits */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid mask %s", mask);
			return -3; /*< Fail */
		}
	}

	/* Generate rule record */
	tmp = safe_malloc(sizeof(t_firewall_rule));
	memset((void *)tmp, 0, sizeof(t_firewall_rule));
	tmp->target = target;
	if (protocol != NULL)
		tmp->protocol = safe_strdup(protocol);
	if (port != NULL)
		tmp->port = safe_strdup(port);
	if (mask == NULL)
		tmp->mask = safe_strdup("0.0.0.0/0");
	else
		tmp->mask = safe_strdup(mask);

	debug(LOG_DEBUG, "Adding Firewall Rule %s %s port %s to %s", token, tmp->protocol, tmp->port, tmp->mask);

	/* Append the rule record */
	if (config.rulesets == NULL) {
		config.rulesets = safe_malloc(sizeof(t_firewall_ruleset));
		memset(config.rulesets, 0, sizeof(t_firewall_ruleset));
		config.rulesets->name = safe_strdup(ruleset);
		tmpr = config.rulesets;
	} else {
		tmpr2 = tmpr = config.rulesets;
		while (tmpr != NULL && (strcmp(tmpr->name, ruleset) != 0)) {
			tmpr2 = tmpr;
			tmpr = tmpr->next;
		}
		if (tmpr == NULL) {
			/* Rule did not exist */
			tmpr = safe_malloc(sizeof(t_firewall_ruleset));
			memset(tmpr, 0, sizeof(t_firewall_ruleset));
			tmpr->name = safe_strdup(ruleset);
			tmpr2->next = tmpr;
		}
	}

	/* At this point, tmpr == current ruleset */
	if (tmpr->rules == NULL) {
		/* No rules... */
		tmpr->rules = tmp;
	} else {
		tmp2 = tmpr->rules;
		while (tmp2->next != NULL)
			tmp2 = tmp2->next;
		tmp2->next = tmp;
	}

	return 1;
}

t_firewall_rule *
get_ruleset(const char *ruleset)
{
	t_firewall_ruleset	*tmp;

	for (tmp = config.rulesets; tmp != NULL
			&& strcmp(tmp->name, ruleset) != 0; tmp = tmp->next);

	if (tmp == NULL)
		return NULL;

	return(tmp->rules);
}

/**
@param filename Full path of the configuration file to be read
*/
void
config_read(const char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2;
	int linenum = 0, opcode, value, len;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "Could not open configuration file '%s', "
				"exiting...", filename);
		exit(1);
	}

	while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
		linenum++;
		s = line;

		if (s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = '\0';

		if ((p1 = strchr(s, ' '))) {
			p1[0] = '\0';
		} else if ((p1 = strchr(s, '\t'))) {
			p1[0] = '\0';
		}

		if (p1) {
			p1++;

			// Trim leading spaces
			len = strlen(p1);
			while (*p1 && len) {
				if (*p1 == ' ')
					p1++;
				else
					break;
				len = strlen(p1);
			}


			if ((p2 = strchr(p1, ' '))) {
				p2[0] = '\0';
			} else if ((p2 = strstr(p1, "\r\n"))) {
				p2[0] = '\0';
			} else if ((p2 = strchr(p1, '\n'))) {
				p2[0] = '\0';
			}
		}

		if (p1 && p1[0] != '\0') {
			/* Strip trailing spaces */

			if ((strncmp(s, "#", 1)) != 0) {
				debug(LOG_DEBUG, "Parsing token: %s, "
						"value: %s", s, p1);
				opcode = config_parse_token(s, filename, linenum);

				switch(opcode) {
				case oDaemon:
					if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
						config.daemon = value;
					}
					break;
				case oExternalInterface:
                    careful_free(config.external_interface);
					config.external_interface = safe_strdup(p1);
					break;
				case oGatewayID:
					config.gw_id = safe_strdup(p1);
					break;
				case oGatewayInterface:
					config.gw_interface = safe_strdup(p1);
					break;
				case oGatewayAddress:
					config.gw_address = safe_strdup(p1);
					break;
				case oGatewayPort:
					sscanf(p1, "%d", &config.gw_port);
					break;
				case oAuthServer:
					parse_auth_server(fd, filename,
							&linenum);
					break;
                case oAppServer: /* cjpthree@126.com 2015.5.13 */
                    parse_app_server(fd, filename, &linenum);
                    break;
				case oFirewallRuleSet:
					parse_firewall_ruleset(p1, fd, filename, &linenum);
					break;
				case oTrustedMACList:
					parse_trusted_mac_list(p1);
					break;
				case oHTTPDName:
					config.httpdname = safe_strdup(p1);
					break;
				case oHTTPDMaxConn:
					sscanf(p1, "%d", &config.httpdmaxconn);
					break;
				case oHTTPDRealm:
					config.httpdrealm = safe_strdup(p1);
					break;
				case oHTTPDUsername:
					config.httpdusername = safe_strdup(p1);
					break;
				case oHTTPDPassword:
					config.httpdpassword = safe_strdup(p1);
					break;
				case oBadOption:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
				case oCheckInterval:
					sscanf(p1, "%d", &config.checkinterval);
					break;
				case oWdctlSocket:
					free(config.wdctl_sock);
					config.wdctl_sock = safe_strdup(p1);
					break;
				case oClientTimeout:
					sscanf(p1, "%d", &config.clienttimeout);
					break;
                case oAutoSsid:
                    sscanf(p1, "%d", &config.autoSsid);
                    break;
                case oAutoPassword:
                    sscanf(p1, "%d", &config.autoPassword);
                    break;
                case oAuto_wireless_pw:
                    sscanf(p1, "%d", &config.autoWirelessPw);
                    break;
                case oQos_enable:
                    sscanf(p1, "%d", &config.qosEnable);
                    break;
                case oUplink_vip:
                    sscanf(p1, "%d", &config.uplinkVip);
                    debug(LOG_DEBUG, "get uplinkVip %d", config.uplinkVip);
                    break;
                case oDownlink_vip:
                    sscanf(p1, "%d", &config.downlinkVip);
                    debug(LOG_DEBUG, "get downlinkVip %d", config.downlinkVip);
                    break;
                case oUplink_common:
                    sscanf(p1, "%d", &config.uplinkCommon);
                    debug(LOG_DEBUG, "get uplinkCommon %d", config.uplinkCommon);
                    break;
                case oDownlink_common:
                    sscanf(p1, "%d", &config.downlinkCommon);
                    debug(LOG_DEBUG, "get downlinkCommon %d", config.downlinkCommon);
                    break;
                case oThreadWatchdogTimeout:
                    sscanf(p1, "%d", &config.threadWatchdogTimeout);
                    break;
				case oSyslogFacility:
					sscanf(p1, "%d", &config.syslog_facility);
					break;
				case oHtmlMessageFile:
                    careful_free(config.htmlmsgfile);
					config.htmlmsgfile = safe_strdup(p1);
					break;
				case oProxyPort:
					sscanf(p1, "%d", &config.proxy_port);
					break;
				case owd_auth_mode:
				    sscanf(p1, "%d", &config.wd_auth_mode);
					break;
                case owd_wechat_forceAttention:
					sscanf(p1, "%d", &config.wd_wechat_forceAttention);
					break;
                case owd_wechat_officialAccount:
                    careful_free(config.wd_wechat_officialAccount);
                    config.wd_wechat_officialAccount = safe_strdup(p1);
					break;
				case owd_wechat_shopId:
                    careful_free(config.wd_wechat_shopId);
                    config.wd_wechat_shopId = safe_strdup(p1);
					break;
				case owd_wechat_appId:
                    careful_free(config.wd_wechat_appId);
                    config.wd_wechat_appId = safe_strdup(p1);
					break;
				case owd_wechat_secretKey:
                    careful_free(config.wd_wechat_secretKey);
                    config.wd_wechat_secretKey = safe_strdup(p1);
					break;
				case owd_wechat_extend:
                    careful_free(config.wd_wechat_extend);
                    config.wd_wechat_extend = safe_strdup(p1);
					break;
				case owd_to_url:
				    careful_free(config.wd_to_url);
                    config.wd_to_url = safe_strdup(p1);
					break;
				case owd_skip_SuccessPage:
				    sscanf(p1, "%d", &config.wd_skip_SuccessPage);
					break;
				case owd_reAssoc_reAuth:
				    sscanf(p1, "%d", &config.wd_reAssoc_reAuth);
					break;
                case oaudit_enable:
			        sscanf(p1, "%d", &config.audit_enable);
				    break;

			    default:
			        break;
				}
			}
		}
	}

	if (config.httpdusername && !config.httpdpassword) {
		debug(LOG_ERR, "HTTPDUserName requires a HTTPDPassword to be set.");
		exit(-1);
	}

	fclose(fd);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
	if (strcasecmp(line, "yes") == 0) {
		return 1;
	}
	if (strcasecmp(line, "no") == 0) {
		return 0;
	}
	if (strcmp(line, "1") == 0) {
		return 1;
	}
	if (strcmp(line, "0") == 0) {
		return 0;
	}

	return -1;
}

void parse_trusted_mac_list(const char *ptr) {
	char *ptrcopy = NULL;
	char *possiblemac = NULL;
	char *mac = NULL;
	t_trusted_mac *p = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

	mac = safe_malloc(18);

	/* strsep modifies original, so let's make a copy */
	ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", "))) {
		if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
			/* Copy mac to the list */

			debug(LOG_DEBUG, "Adding MAC address [%s] to trusted list", mac);

			if (config.trustedmaclist == NULL) {
				config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
				config.trustedmaclist->mac = safe_strdup(mac);
				config.trustedmaclist->next = NULL;
			}
			else {
				/* Advance to the last entry */
				for (p = config.trustedmaclist; p->next != NULL; p = p->next);
				p->next = safe_malloc(sizeof(t_trusted_mac));
				p = p->next;
				p->mac = safe_strdup(mac);
				p->next = NULL;
			}

		}
	}

	free(ptrcopy);

	free(mac);

}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	config_notnull(config.gw_interface, "GatewayInterface");
	config_notnull(config.auth_servers, "AuthServer");

	if (missing_parms) {
		debug(LOG_ERR, "Configuration is not complete, exiting...");
		exit(-1);
	}

	if (config.wd_to_url == NULL) {
	    config.wd_to_url = DUMY_REQ_URL;
	}
	if (!strstr(config.wd_to_url, "://")) {
	    char url[MAX_RECORD_URL_LEN] = {0};
	    memcpy(url, "http://", strlen("http://"));
	    strcat(url, config.wd_to_url);
	    careful_free(config.wd_to_url);
        config.wd_to_url = safe_strdup(url);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char *parmname)
{
	if (parm == NULL) {
		debug(LOG_ERR, "%s is not set", parmname);
		missing_parms = 1;
	}
}

/**
 * This function returns the current (first auth_server)
 */
t_auth_serv *
get_auth_server(void)
{
	/* This is as good as atomic */
	return config.auth_servers;
}

/**
 * This function returns the current (first app_server)
 */
t_app_serv *
get_app_server(void)
{
	/* This is as good as atomic */
	return config.app_servers;
}


/**
 * This function marks the current auth_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 */
void
mark_auth_server_bad(t_auth_serv *bad_server)
{
	t_auth_serv	*tmp;

    debug(LOG_DEBUG, "mark_auth_server_bad");
	if (config.auth_servers == bad_server && bad_server->next != NULL) {
		/* Go to the last */
		for (tmp = config.auth_servers; tmp->next != NULL; tmp = tmp->next);
		/* Set bad server as last */
		tmp->next = bad_server;
		/* Remove bad server from start of list */
		config.auth_servers = bad_server->next;
		/* Set the next pointe to NULL in the last element */
		bad_server->next = NULL;
	}
}

/**
 * This function marks the current auth_server, if it matches the argument,
 * as optimal. Basically, the "optimal" server becomes the first one on the list.
 * optimal_server can be anywhere of the list, or not in the list.
 * cjpthree@126.com 2015.5.13
 */
void
elect_optimal_auth_server(t_auth_serv *optimal_server)
{
    t_auth_serv	*tmp;
    t_auth_serv	*tmp_pre;

    debug(LOG_DEBUG, "elect_optimal_auth_server");

    if (!optimal_server || config.auth_servers == optimal_server) {
        debug(LOG_DEBUG, "do nothing");
        return;
    }

    /* in the list, set it as first one */
    for (tmp = config.auth_servers, tmp_pre = config.auth_servers; tmp; tmp_pre = tmp, tmp = tmp->next) {
        if (!memcmp(tmp, optimal_server, sizeof(t_auth_serv))) {
            tmp_pre->next = tmp->next;
            tmp->next = config.auth_servers;
            config.auth_servers = tmp;
            return;
        }
    }

    /* can not find in the auth_severs list, add the the first position delectly */
    if (config.auth_servers->next) {
        optimal_server->next = config.auth_servers->next;
        config.auth_servers = optimal_server;
    }
}

/**
 * This function marks the current app_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 * and the next one move to the first.
 * cjpthree@126.com 2015.5.13
 */
void
mark_app_server_bad(t_app_serv *bad_server)
{
	t_app_serv	*tmp;

	if (config.app_servers == bad_server && bad_server->next != NULL) {
		/* Go to the last */
		for (tmp = config.app_servers; tmp->next != NULL; tmp = tmp->next);
		/* Set bad server as last */
		tmp->next = bad_server;
		/* Remove bad server from start of list */
		config.app_servers = bad_server->next;
		/* Set the next pointe to NULL in the last element */
		bad_server->next = NULL;
	}
}

