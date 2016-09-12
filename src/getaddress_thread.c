/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * getaddress_thread.c
 * Original Author : cjpthree@126.com, 2015-5-7.
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

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "util.h"
#include "centralserver.h"
#include "http.h"
#include "getaddress_thread.h"
#include "list.h"

#ifdef __OPENWRT__
#include <uci_config.h>
#include <uci.h>
#endif


#define DEF_AUTHSERVPATH "/AuthenServer/interface/"
#define PATH_APPEND_SEGEMENT "interface"
#define GET_ADDRESS_THREAD_TIMEOUT (12 * 60 * 60UL)


typedef struct server_address_s {
    char protocol[20];
    char ip[128];
    char port[10];
    char path[128];
    int iport;
    int optimal_flag;
} server_address_t;

typedef struct server_address_node_s {
    server_address_t address;
    struct dlist_head list;
} server_address_node_t;

typedef int (*PROCESS_t)(char *);

static int cmm_getaddress();
static int getaddressCommand( char *request, PROCESS_t funcProcess);
static int  proc_getaddress(char *reponse);
static int parse_address(char *reponse);
static void apply_address(void);
static int regularize_address(server_address_node_t *new_node);
static void update_authserv_list(void);
static void elect_optimal_authserver();
static void write_authserv_config();
static t_auth_serv *generate_auth_server(server_address_node_t *node);
static int join_option_name(char *buf, const char *name, int number);
static void destory_server_list();


pthread_cond_t          get_address_thread_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t         get_address_thread_cond_mutex = PTHREAD_MUTEX_INITIALIZER;


static dlist_head_t server_list; /* save the auth severs list. only this thread operating this list, so avoid lock */


void thread_getaddress(char *arg)
{
    struct  timespec        timeout;
    static int run_count;

    INIT_DLIST_HEAD(&server_list);

    while (1) {
#if 1
        timeout.tv_sec = time(NULL) + GET_ADDRESS_THREAD_TIMEOUT; /* realse should using this setting */
#else
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
#endif
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&get_address_thread_cond_mutex);

        if (run_count++) {              /* did not need to sleep first time */
            /* Thread safe "sleep" */
            pthread_cond_timedwait(&get_address_thread_cond, &get_address_thread_cond_mutex, &timeout);
        }

        if (cmm_getaddress() != 0)
        {
            printf( "get server address fail \n");
        }

        /* No longer needs to be locked */
        pthread_mutex_unlock(&get_address_thread_cond_mutex);
    }
    destory_server_list();
}

static int cmm_getaddress()
{
    static char request[MAX_BUF];
    t_app_serv *app_server = get_app_server();
    system_info_t info;

    memset(request, 0, MAX_BUF);
    memset((void *)&info, 0, sizeof(system_info_t));
    if (get_system_info(&info)) {
        debug(LOG_ERR, "fail to do get_system_info");
    }

    /*
     * Prep & send request
     */
    snprintf(request, sizeof(request) - 1,
            "GET %s%ssoftwareName=%s&currentVersion=%s&SNID=%s HTTP/1.0\r\n"
            "User-Agent: FirmwareUpdate %s\r\n"
            "Host: %s\r\n"
            "\r\n",
            app_server->appserv_path, // "/appServer/interface/",
            app_server->appserv_get_address_path_fragment, //"getaddress/?",
            info.model,
            info.version,
            info.snid,
            VERSION,
            app_server->appserv_hostname);
            debug(LOG_DEBUG, "========== request ======: [%s]", request);

    return getaddressCommand(request,proc_getaddress);
}

static int getaddressCommand( char *request, PROCESS_t funcProcess)
{
    int sockfd,nfds, done;
    ssize_t numbytes;
    size_t    totalbytes;
    fd_set  readfds;
    struct timeval  timeout;

    sockfd = connect_app_server();
    if (sockfd == -1) {
    /*
     * No app servers for me to talk to
     */
        return ERR_noServer;
    }
    // send request
    debug(LOG_DEBUG, "Send request");
    send(sockfd, request, strlen(request), 0);
    // read reponse
    debug(LOG_DEBUG, "Reading response");
    numbytes = totalbytes = 0;
    done =0;
    do
    {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = 30; /* XXX magic... 30 second */
        timeout.tv_usec = 0;
        nfds = sockfd + 1;

        nfds = select(nfds, &readfds, NULL, NULL, &timeout);

        if (nfds > 0)
        {
            /** We don't have to use FD_ISSET() because there
             *  was only one fd. */
            numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
            if (numbytes < 0)
            {
                debug(LOG_ERR, "An error occurred while reading from app server: %s", strerror(errno));
                /* FIXME */
                close(sockfd);
                return ERR_READ;
            }
            else if (numbytes == 0)
            {
                done = 1;
            }
            else
            {
                totalbytes += numbytes;
                debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
            }
        }
        else if (nfds == 0){
            debug(LOG_ERR, "Timed out reading data via select() from app server");
            /* FIXME */
            close(sockfd);
            return ERR_TIMEOUT;
        }
        else if (nfds < 0){
            debug(LOG_ERR, "Error reading data via select() from app server: %s", strerror(errno));
            /* FIXME */
            close(sockfd);
            return ERR_READ;
        }
    }while (!done);
    request[totalbytes] = '\0';
    close(sockfd);
    // process the reponse
    debug(LOG_DEBUG, "HTTP Response from app Server:[%s]", request);
    return funcProcess(request);
}

static int  proc_getaddress(char *reponse)
{
    debug(LOG_DEBUG, "reponse:\n%s", reponse);
    if (strstr(reponse, "Pong") == 0)
    {
        debug(LOG_WARNING, "Not pong, you should set auth adress!");
        parse_address(reponse);
        apply_address();
    }
    else
    {
        debug(LOG_DEBUG, "Pong, Auth adress need not to set");
    }
    return OK;
}

static int parse_address(char *reponse)
{
    static server_address_node_t new_node;
    static server_address_node_t *new_server;
    server_address_node_t *pos;
    char *curr;
    int exist_flag;
    int have_optimal_flag; /* set the getting first server as optimal one, marked if found it */

    if (!reponse) {
        return -1;
    }
    debug(LOG_DEBUG, "parse address");

    curr = reponse;
    have_optimal_flag = 0;
    while ((curr = strstr(curr, "http://")))
    {
        memset(&new_node, 0, sizeof(server_address_node_t));
        debug(LOG_DEBUG, "the start str is %s", curr);
        sscanf(curr, "%[^:]://%[^:]:%[0-9]%[^,\r\n]",
            new_node.address.protocol, new_node.address.ip, new_node.address.port, new_node.address.path);

        /* check valid basic */
        if (!strlen(new_node.address.ip) || !strlen(new_node.address.port)) {
            continue;
        }

        /* regularize */
        regularize_address(&new_node);

        /* set the receiving first one as optimal */
        if (!have_optimal_flag) {
            new_node.address.optimal_flag = 1;
            have_optimal_flag = 1;
        }

        exist_flag = 0;
        /* if only did not have the same node in the list, then add to the list */
        dlist_for_each_entry(pos, &server_list, server_address_node_t, list) {
            if (!strncasecmp(pos->address.protocol, new_node.address.protocol, strlen(new_node.address.protocol) + 1)
                && !strncasecmp(pos->address.ip, new_node.address.ip, strlen(new_node.address.ip) + 1)
                && !strncasecmp(pos->address.port, new_node.address.port, strlen(new_node.address.port) + 1)
                /* && !strncasecmp(pos->address.path, new_node.address.path, strlen(new_node.address.path) + 1) */) {
                exist_flag = 1;
                break;
            }
        }

        if (!exist_flag) {
            new_server = (server_address_node_t *)safe_malloc(sizeof(server_address_node_t));
            memset(new_server, 0, sizeof(server_address_node_t));
            memcpy(new_server, &new_node, sizeof(server_address_node_t));
            debug(LOG_DEBUG, "adding new server to list, protocol %s, ip %s, port %s, path %s, iport %d",
                new_server->address.protocol, new_server->address.ip, new_server->address.port, new_server->address.path, new_server->address.iport);
            if (new_server->address.optimal_flag) {
                dlist_add(&new_server->list, &server_list); /* the optimal one set as the first */
            } else {
                dlist_add_tail(&new_server->list, &server_list);
            }
            new_server = NULL;
        }

        curr = curr + strlen("http://");
    }

    return 0;
}

static void apply_address(void)
{
    update_authserv_list();
    elect_optimal_authserver();
    write_authserv_config();
}

static int regularize_address(server_address_node_t *new_node)
{
    new_node->address.iport = atoi(new_node->address.port);
    debug(LOG_DEBUG, "getting protocol %s, ip %s, port %s, path %s, iport %d",
        new_node->address.protocol, new_node->address.ip, new_node->address.port, new_node->address.path, new_node->address.iport);
    if (!strlen(new_node->address.path)) {
        debug(LOG_DEBUG, "the address path is null, using %s replace", DEF_AUTHSERVPATH);
        memcpy(new_node->address.path, DEF_AUTHSERVPATH, strlen(DEF_AUTHSERVPATH));
    }
    if (new_node->address.path[0] != '/') {
        //add /
        debug(LOG_DEBUG, "add / before the getting address path");
        memmove(new_node->address.path + 1, new_node->address.path, strlen(new_node->address.path));
        new_node->address.path[0] = '/';
    }
    if (!strchr(new_node->address.path + 1, '/')) {
        // add /interface/
        debug(LOG_DEBUG, "add /interface/ after the getting address path");
        strcat(new_node->address.path, "/");
        strcat(new_node->address.path, PATH_APPEND_SEGEMENT);
        strcat(new_node->address.path, "/");
    } else if (strchr(new_node->address.path + 1, '/') == (new_node->address.path + strlen(new_node->address.path) - 1)) {
        // add interface/
        debug(LOG_DEBUG, "add interface/ after the getting address path");
        strcat(new_node->address.path, PATH_APPEND_SEGEMENT);
        strcat(new_node->address.path, "/");
    }
    if (new_node->address.path[strlen(new_node->address.path) - 1] != '/') {
        // add /
        debug(LOG_DEBUG, "add / after the getting address path");
        strcat(new_node->address.path, "/");
    }

    //strcpy(new_node->address.ip, "192.168.2.3"); // for debug
    return 0;
}

static void update_authserv_list(void)
{
    server_address_node_t *pos;
    t_auth_serv	*auth_servers = config_get_config()->auth_servers;
    t_auth_serv	*auth_tmp;
    t_auth_serv *new_server;
    int exist_flag;

    dlist_for_each_entry(pos, &server_list, server_address_node_t, list) {
        debug(LOG_DEBUG, "the ip is %s, port is %s, iport is %d", pos->address.ip, pos->address.port, pos->address.iport);
        /* check exist, and add to wifidog autu list */
        if (auth_servers == NULL) {
            debug(LOG_DEBUG, "have not auth server yet, add auth server");
            new_server = generate_auth_server(pos);
            if (new_server) {
                auth_servers = new_server;
            }
	    } else {
	        exist_flag = 0;
            /* check if auth server list had this auth server */
		    for (auth_tmp = auth_servers; auth_tmp != NULL; auth_tmp = auth_tmp->next) {
                debug(LOG_DEBUG, "check auth server list, auth_tmp hostname %s, port %d, path %s",
                    auth_tmp->authserv_hostname, auth_tmp->authserv_http_port, auth_tmp->authserv_path);
                if (!strncasecmp(pos->address.ip, auth_tmp->authserv_hostname, strlen(pos->address.ip) + 1)
                    && (pos->address.iport == auth_tmp->authserv_http_port)
                    /*&& !strncasecmp(pos->address.path, auth_tmp->authserv_path, strlen(pos->address.path) + 1)*/) {
                    exist_flag = 1;
                    break;
                }
            }

            if (!exist_flag) {
                debug(LOG_DEBUG, "not exist, add auth server");
                new_server = generate_auth_server(pos);
                if (new_server) {
    		        for (auth_tmp = auth_servers; auth_tmp->next != NULL; auth_tmp = auth_tmp->next);
		            auth_tmp->next = new_server;
                }
            }
	    }
    }
}

static void elect_optimal_authserver()
{
    server_address_node_t *first_auth;
    t_auth_serv	*auth_servers = config_get_config()->auth_servers;
    t_auth_serv	*auth_tmp;

    if (dlist_empty(&server_list)) {
        debug(LOG_DEBUG, "server_list have nothing");
        return;
    }

    first_auth = dlist_first_entry(&server_list, server_address_node_t, list);
    for (auth_tmp = auth_servers; auth_tmp != NULL; auth_tmp = auth_tmp->next) {
        debug(LOG_DEBUG, "elect_optimal_authserver, auth_tmp hostname %s, port %d, path %s",
            auth_tmp->authserv_hostname, auth_tmp->authserv_http_port, auth_tmp->authserv_path);
        if (!strncasecmp(first_auth->address.ip, auth_tmp->authserv_hostname, strlen(first_auth->address.ip) + 1)
            && (first_auth->address.iport == auth_tmp->authserv_http_port)
            /*&& !strncasecmp(pos->address.path, auth_tmp->authserv_path, strlen(pos->address.path) +1)*/) {
            elect_optimal_auth_server(auth_tmp);
            break;
        }
    }
}

/* use uci api to write wifidog config file */
static void write_authserv_config()
{
    t_auth_serv	*auth_servers = config_get_config()->auth_servers;
    t_auth_serv	*auth_tmp;
    char option_name[20];
    char value[128];
    int i;
    struct uci_context * ctx = uci_alloc_context();
    struct uci_ptr ptr ={
        .package = "wifidog",
        .section = "wifidog",
        .option = option_name,
        .value = value,
    };

    for (auth_tmp = auth_servers, i = 0; auth_tmp != NULL; auth_tmp = auth_tmp->next, i++) {
        debug(LOG_DEBUG, "write_authserv_config, auth_tmp hostname %s, port %d, path %s",
            auth_tmp->authserv_hostname, auth_tmp->authserv_http_port, auth_tmp->authserv_path);

        memset(option_name, 0, sizeof(option_name) / sizeof(option_name[0]));
        memset(value, 0, sizeof(value) / sizeof(value[0]));
        join_option_name(option_name, "gateway_hostname", i);
        memcpy(value, auth_tmp->authserv_hostname, strlen(auth_tmp->authserv_hostname));
        debug(LOG_DEBUG, "uci set: %s %s %s %s",
            ptr.package, ptr.section, ptr.option, ptr.value);
        uci_set(ctx, &ptr);

        memset(option_name, 0, sizeof(option_name) / sizeof(option_name[0]));
        memset(value, 0, sizeof(value) / sizeof(value[0]));
        join_option_name(option_name, "gateway_httpport", i);
        sprintf(value, "%d", auth_tmp->authserv_http_port);
        debug(LOG_DEBUG, "uci set: %s %s %s %s",
            ptr.package, ptr.section, ptr.option, ptr.value);
        uci_set(ctx, &ptr);

        memset(option_name, 0, sizeof(option_name) / sizeof(option_name[0]));
        memset(value, 0, sizeof(value) / sizeof(value[0]));
        join_option_name(option_name, "gateway_path", i);
        memcpy(value, auth_tmp->authserv_path, strlen(auth_tmp->authserv_path));
        debug(LOG_DEBUG, "uci set: %s %s %s %s",
            ptr.package, ptr.section, ptr.option, ptr.value);
        uci_set(ctx, &ptr);
    }

    uci_commit(ctx, &ptr.p, false);
    uci_unload(ctx, ptr.p);

    uci_free_context(ctx);
}

static t_auth_serv *generate_auth_server(server_address_node_t *node)
{
    t_auth_serv *new_server;

    if (!node) {
        debug(LOG_ERR, "invalid address, node %p", node);
        return NULL;
    }
    debug(LOG_DEBUG, "generating a new auth server, ip %s, port %d, path %s",
        node->address.ip, node->address.iport, node->address.path);

    new_server = (t_auth_serv *)safe_malloc(sizeof(t_auth_serv));
	memset(new_server, 0, sizeof(t_auth_serv)); /*< Fill all with NULL */
	new_server->authserv_hostname = safe_strdup(node->address.ip);
	new_server->authserv_path = safe_strdup(node->address.path);
	new_server->authserv_login_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
	new_server->authserv_portal_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
	new_server->authserv_msg_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
	new_server->authserv_ping_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
	new_server->authserv_auth_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
	new_server->authserv_update_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVUPDATEPATHFRAGMENT);
	new_server->authserv_download_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVDOWNLOADPATHFRAGMENT);
	new_server->authserv_config_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVCONFIGPATHFRAGMENT);
	new_server->authserv_authmac_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVAUTHMACPATHFRAGMENT);
	new_server->authserv_http_port = node->address.iport;
	new_server->authserv_ssl_port = DEFAULT_AUTHSERVSSLPORT;
	new_server->authserv_use_ssl = DEFAULT_AUTHSERVSSLAVAILABLE;

    return new_server;
}

static int join_option_name(char *buf, const char *name, int number)
{
    if (number == 0) {
        sprintf(buf, "%s", name);
        return 0;
    }

    sprintf(buf, "%s%d", name, number);
    return 0;
}

static void destory_server_list()
{
    struct dlist_head *pos, *ptmp;
    server_address_node_t *pos_node;
    dlist_for_each_safe(pos, ptmp, &server_list) {
        pos_node = dlist_entry(pos, server_address_node_t, list);
        dlist_del(pos);
        free(pos_node);
    }
}

