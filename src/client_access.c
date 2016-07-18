/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * client_access.c
 * Original Author : cjpthree@126.com, 2015-6-26.
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
#include "client_list.h"
#include "firewall.h"
#include "get_client.h"
#include "client_access_preproccess.h"
#include "client_access_queue.h"


int thread_client_access(char *arg)
{
    unsigned char mac[MAC_ADDR_LEN];

    while(1)
    {
        memset(mac, 0, MAC_ADDR_LEN);
        sem_wait(&sem_client_access_preproccess);
        if (client_access_queue_dequeue(mac)) {
            debug(LOG_WARNING, "fail to get mac\n");
            continue;
        }
        debug(LOG_DEBUG, "get mac %s, ask server later\n", mac);

        (void)client_access(mac);
    }

    return 0;
}

static int client_access_command( char *request, int *auth)
{
    int sockfd,nfds, done;
    ssize_t numbytes;
    size_t    totalbytes;
    fd_set  readfds;
    struct timeval  timeout;

    sockfd = connect_auth_server();
    if (sockfd == -1) {
    /*
     * No auth servers for me to talk to
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
                debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
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
            debug(LOG_ERR, "Timed out reading data via select() from auth server");
            /* FIXME */
            close(sockfd);
            return ERR_TIMEOUT;
        }
        else if (nfds < 0){
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            /* FIXME */
            close(sockfd);
            return ERR_READ;
        }
    }while (!done);
    request[totalbytes] = '\0';
    close(sockfd);
    // process the reponse
    debug(LOG_DEBUG, "HTTP Response from Server:[%s]", request);

    char authmac[MAC_ADDR_LEN] = {0};
    if (strstr(request, "Auth: "))
    {
        getKeyvalue(authmac, request, "Auth: ");
        debug(LOG_DEBUG, "Auth: [%s]", authmac);
    }

    *auth = atoi(authmac);
    return OK;
}

static int cmm_client_access(char *mac, int *auth)
{
    static char request[MAX_BUF]={0};
    t_auth_serv *auth_server = get_auth_server();

    memset(request, 0, MAX_BUF);

    /*
     * Prep & send request
     */
    snprintf(request, sizeof(request) - 1,
            "GET %s%smac=%s&gw_id=%s HTTP/1.0\r\n"
            "User-Agent: FirmwareUpdate %s\r\n"
            "Host: %s\r\n"
            "\r\n",
            auth_server->authserv_path,
            auth_server->authserv_authmac_script_path_fragment,
            mac,
            config_get_config()->gw_id,
            VERSION,
            auth_server->authserv_hostname);
            debug(LOG_DEBUG, "request: [%s]", request);

    return client_access_command(request, auth);
}

int client_access(char *mac)
{
    int access;
    int auth;

    if(OK != cmm_client_access(mac, &access)) {
        debug(LOG_DEBUG, "fail to get auth status from auth server for [%s]", mac);
        (void)client_list_set_last_updated(mac, time(NULL));
        (void)iptables_fw_tracked_mac(mac);
        return -1;
    }

    switch (access) {
    case 2: /* VIP */
        debug(LOG_DEBUG, "[%s] is VIP", mac);
        (void)client_list_set_auth(mac, CLIENT_VIP);
        (void)iptables_fw_allow_mac(mac);
        break;
    case 1: /* success, not VIP */
        debug(LOG_DEBUG, "[%s] auth success, but not VIP", mac);
        (void)client_list_set_auth(mac, CLIENT_COMMON);
        (void)iptables_fw_allow_mac(mac);
        break;
    default: /* fail */
        debug(LOG_DEBUG, "[%s] auth fail", mac);
        /* fixbug: get whitelist_mac when asking auth server */
        if (client_list_get_auth(mac, &auth)) {
            auth = CLIENT_UNAUTH;
        }
        if (auth >= CLIENT_CONFIG) {
            debug(LOG_DEBUG, "mac %s is in config, can not delete", mac);
            break;
        }
        (void)client_list_set_auth(mac, CLIENT_UNAUTH);
        (void)iptables_fw_deny_mac(mac);
        break;
    }

    (void)iptables_fw_tracked_mac(mac);

    return 0;
}

