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
/** @file wdctl_thread.c
    @brief Monitoring and control of wifidog, server part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "common.h"
#include "httpd.h"
#include "util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "gateway.h"
#include "safe.h"
#include "client_record_queue.h"
#include "click_record_queue.h"


/* From commandline.c: */
extern char ** restartargv;
static void *thread_wdctl_handler(void *);
static void wdctl_status(int);
static void wdctl_status_goahead(int fd);
static void wdctl_client_record(int fd);
static void wdctl_click_record(int fd);
static void wdctl_stop(int);
static void wdctl_reset(int, const char *);
static void wdctl_restart(int);
static void wdctl_delete_client(int fd, const char *arg);
static void wdctl_set_client(int fd, const char *arg);
static void wdctl_check(int fd);
static void wdctl_print(int fd);
static void wdctl_syslog(int fd);


/** Launches a thread that monitors the control socket for request
@param arg Must contain a pointer to a string containing the Unix domain socket to open
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_wdctl(void *arg)
{
	int	*fd;
	char	*sock_name;
	struct 	sockaddr_un	sa_un;
	int result;
	pthread_t	tid;
	socklen_t len;

	memset(&sa_un, 0, sizeof(sa_un));
	sock_name = (char *)arg;
	debug(LOG_DEBUG, "Socket name: %s", sock_name);

	if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
		/* TODO: Die handler with logging.... */
		debug(LOG_ERR, "WDCTL socket name too long");
		exit(1);
	}


	debug(LOG_DEBUG, "Creating socket");
	wdctl_socket_server = socket(PF_UNIX, SOCK_STREAM, 0);

	debug(LOG_DEBUG, "Got server socket %d", wdctl_socket_server);

	/* If it exists, delete... Not the cleanest way to deal. */
	unlink(sock_name);

	debug(LOG_DEBUG, "Filling sockaddr_un");
	strcpy(sa_un.sun_path, sock_name); /* XXX No size check because we
					    * check a few lines before. */
	sa_un.sun_family = AF_UNIX;

	debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path,
			strlen(sock_name));

	/* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
	if (bind(wdctl_socket_server, (struct sockaddr *)&sa_un, strlen(sock_name)
				+ sizeof(sa_un.sun_family))) {
		debug(LOG_ERR, "Could not bind control socket: %s",
				strerror(errno));
		pthread_exit(NULL);
	}

	if (listen(wdctl_socket_server, 5)) {
		debug(LOG_ERR, "Could not listen on control socket: %s",
				strerror(errno));
		pthread_exit(NULL);
	}

	while (1) {
		len = sizeof(sa_un);
		memset(&sa_un, 0, len);
		fd = (int *) safe_malloc(sizeof(int));
		if ((*fd = accept(wdctl_socket_server, (struct sockaddr *)&sa_un, &len)) == -1){
			debug(LOG_ERR, "Accept failed on control socket: %s",
					strerror(errno));
			free(fd);
		} else {
			/* debug(LOG_DEBUG, "Accepted connection on wdctl socket %d (%s)", fd, sa_un.sun_path); */
			result = pthread_create(&tid, NULL, &thread_wdctl_handler, (void *)fd);
			if (result != 0) {
				debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl handler) - exiting");
				free(fd);
				termination_handler(0);
			}
			pthread_detach(tid);
		}
	}
}


static void *
thread_wdctl_handler(void *arg)
{
	int	fd,
		done,
		i;
	char	request[MAX_BUF];
	ssize_t	read_bytes,
		len;

	debug(LOG_DEBUG, "Entering thread_wdctl_handler....");

	fd = *((int *) arg);
	free(arg);
	/*debug(LOG_DEBUG, "Read bytes and stuff from %d", fd);*/

	/* Init variables */
	read_bytes = 0;
	done = 0;
	memset(request, 0, sizeof(request));

	/* Read.... */
	while (!done && read_bytes < (sizeof(request) - 1)) {
		len = read(fd, request + read_bytes,
				sizeof(request) - read_bytes);

		/* Have we gotten a command yet? */
		for (i = read_bytes; i < (read_bytes + len); i++) {
			if (request[i] == '\r' || request[i] == '\n') {
				request[i] = '\0';
				done = 1;
			}
		}

		/* Increment position */
		read_bytes += len;
	}

	/*debug(LOG_DEBUG, "Request received: [%s]", request);*/

	if (strncmp(request, "status", 6) == 0) {
		wdctl_status(fd);
	} else if (strncmp(request, "sts_goahead", 11) == 0) {
		wdctl_status_goahead(fd);
	} else if (strncmp(request, "client_record", 13) == 0) {
		wdctl_client_record(fd);
	} else if (strncmp(request, "click_record", strlen("click_record")) == 0) {
		wdctl_click_record(fd);
	} else if (strncmp(request, "stop", 4) == 0) {
		wdctl_stop(fd);
	} else if (strncmp(request, "reset", 5) == 0) {
		wdctl_reset(fd, (request + 6));
	} else if (strncmp(request, "delete_client", strlen("delete_client")) == 0) {
		wdctl_delete_client(fd, (request + strlen("delete_client") + 1));
	} else if (strncmp(request, "set_client", strlen("set_client")) == 0) {
		wdctl_set_client(fd, (request + strlen("set_client") + 1));
	} else if (strncmp(request, "restart", 7) == 0) {
		wdctl_restart(fd);
	} else if (strncmp(request, "check", 5) == 0) {
		wdctl_check(fd);
	} else if (strncmp(request, "print", 5) == 0) {
		wdctl_print(fd);
	} else if (strncmp(request, "syslog", 6) == 0) {
		wdctl_syslog(fd);
	}

	if (!done) {
		debug(LOG_ERR, "Invalid wdctl request.");
		shutdown(fd, 2);
		close(fd);
		pthread_exit(NULL);
	}

	shutdown(fd, 2);
	close(fd);
	/*debug(LOG_DEBUG, "Exiting thread_wdctl_handler....");*/

	return NULL;
}

static void
wdctl_check(int fd)
{
	if(write(fd, "1", 1) == -1)
		debug(LOG_CRIT, "Write error: %s", strerror(errno));
}

static void
wdctl_print(int fd)
{
    s_config * conf = config_get_config();

    conf->log_print = 1;
    conf->log_location = 1;
    conf->debuglevel = 7;

	if(write(fd, "Yes", 3) == -1) {
		debug(LOG_CRIT, "Unable to write Yes: %s", strerror(errno));
	}
}

static void
wdctl_syslog(int fd)
{
    s_config * conf = config_get_config();

    conf->log_syslog = 1;
    conf->log_location = 1;
    conf->debuglevel = 7;

	if(write(fd, "Yes", 3) == -1) {
		debug(LOG_CRIT, "Unable to write Yes: %s", strerror(errno));
	}
}

static void
wdctl_status(int fd)
{
	char * status = NULL;
	int len = 0;

	status = get_status_text();
	len = strlen(status);

	if(write(fd, status, len) == -1)
		debug(LOG_CRIT, "Write error: %s", strerror(errno));

	free(status);
}

static void
wdctl_status_goahead(int fd)
{
	char * status = NULL;
	int len = 0;

	status = get_status_text_goahead();
	len = strlen(status);

	if(write(fd, status, len) == -1)
		debug(LOG_CRIT, "Write error: %s", strerror(errno));

	free(status);
}

static char *get_client_record(void) {
	char buffer[STATUS_BUF_SIZ];
	ssize_t len = 0;
    client_record_queue_node_t dev;

    while (0 == client_record_queue_dequeue(&dev)) {
        snprintf((buffer + len), (sizeof(buffer) - len), "%s %u\n", dev.mac, dev.assoc_time);
        len = strlen(buffer);
    }

	return safe_strdup(buffer);
}

static char *get_click_record(void) {
    char buffer[STATUS_BUF_SIZ];
    ssize_t len = 0;
    click_record_queue_node_t click;

    while (0 == click_record_queue_dequeue(&click)) {
        snprintf((buffer + len), (sizeof(buffer) - len), "%s %s %d %u\n", click.mac, click.appid, click.type, click.click_time);
        len = strlen(buffer);
    }

    return safe_strdup(buffer);
}

static void wdctl_client_record(int fd)
{
	char * status = NULL;
	int len = 0;

	status = get_client_record();
	len = strlen(status);

	if(write(fd, status, len) == -1)
		debug(LOG_CRIT, "Write error: %s", strerror(errno));

	free(status);
}

static void wdctl_click_record(int fd)
{
	char * status = NULL;
	int len = 0;

	status = get_click_record();
	len = strlen(status);

	if(write(fd, status, len) == -1)
		debug(LOG_CRIT, "Write error: %s", strerror(errno));

	free(status);
}

/** A bit of an hack, self kills.... */
static void
wdctl_stop(int fd)
{
	pid_t	pid;

	pid = getpid();
	kill(pid, SIGINT);
}

static int send_client_list(const client_t *client, void *arg)
{
	char * tempstring = NULL;
    socklen_t len;
    ssize_t written;
    int fd = (int)arg;

	/* Send this client */
	safe_asprintf(&tempstring, "CLIENT|ip=%s|mac=%s|token=%s|auth=%d|fw_state=%u|counters_incoming=%llu|counters_outgoing=%llu\n",
	    client->ip, client->mac, client->token, client->auth, client->fw_state,
	    client->counters.incoming, client->counters.outgoing);
	debug(LOG_DEBUG, "Sending to child client data: %s", tempstring);
	len = 0;
	while (len != strlen(tempstring)) {
		written = write(fd, (tempstring + len), strlen(tempstring) - len);
		if (written == -1) {
			debug(LOG_ERR, "Failed to write client data to child: %s", strerror(errno));
			careful_free(tempstring);
			break;
		}
		else {
			len += written;
		}
	}
	careful_free(tempstring);

    return 0;
}

static void
wdctl_restart(int afd)
{
	int	sock,
		fd;
	char	*sock_name;
	struct 	sockaddr_un	sa_un;
	s_config * conf = NULL;
	char * tempstring = NULL;
	pid_t pid;
	ssize_t written;
	socklen_t len;

	conf = config_get_config();

	debug(LOG_NOTICE, "Will restart myself");

	/*
	 * First, prepare the internal socket
	 */
	memset(&sa_un, 0, sizeof(sa_un));
	sock_name = conf->internal_sock;
	debug(LOG_DEBUG, "Socket name: %s", sock_name);

	if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
		/* TODO: Die handler with logging.... */
		debug(LOG_ERR, "INTERNAL socket name too long");
		return;
	}

	debug(LOG_DEBUG, "Creating socket");
	sock = socket(PF_UNIX, SOCK_STREAM, 0);

	debug(LOG_DEBUG, "Got internal socket %d", sock);

	/* If it exists, delete... Not the cleanest way to deal. */
	unlink(sock_name);

	debug(LOG_DEBUG, "Filling sockaddr_un");
	strcpy(sa_un.sun_path, sock_name); /* XXX No size check because we check a few lines before. */
	sa_un.sun_family = AF_UNIX;

	debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path, strlen(sock_name));

	/* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
	if (bind(sock, (struct sockaddr *)&sa_un, strlen(sock_name) + sizeof(sa_un.sun_family))) {
		debug(LOG_ERR, "Could not bind internal socket: %s", strerror(errno));
		return;
	}

	if (listen(sock, 5)) {
		debug(LOG_ERR, "Could not listen on internal socket: %s", strerror(errno));
		return;
	}

	/*
	 * The internal socket is ready, fork and exec ourselves
	 */
	debug(LOG_DEBUG, "Forking in preparation for exec()...");
	pid = safe_fork();
	if (pid > 0) {
		/* Parent */

		/* Wait for the child to connect to our socket :*/
		debug(LOG_DEBUG, "Waiting for child to connect on internal socket");
		len = sizeof(sa_un);
		if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1){
			debug(LOG_ERR, "Accept failed on internal socket: %s", strerror(errno));
			close(sock);
			return;
		}

		close(sock);

		debug(LOG_DEBUG, "Received connection from child.  Sending them all existing clients");
		/* The child is connected. Send them over the socket the existing clients */
        (void)client_list_traverse(send_client_list, (void *)fd);

		close(fd);

		debug(LOG_INFO, "Sent all existing clients to child.  Committing suicide!");

		shutdown(afd, 2);
		close(afd);

		/* Our job in life is done. Commit suicide! */
		wdctl_stop(afd);
	}
	else {
		/* Child */
		close(wdctl_socket_server);
		close(icmp_fd);
		close(sock);
		shutdown(afd, 2);
		close(afd);
		debug(LOG_NOTICE, "Re-executing myself (%s)", restartargv[0]);
		setsid();
		execvp(restartargv[0], restartargv);
		/* If we've reached here the exec() failed - die quickly and silently */
		debug(LOG_ERR, "I failed to re-execute myself: %s", strerror(errno));
		debug(LOG_ERR, "Exiting without cleanup");
		exit(1);
	}

}

static void
wdctl_reset(int fd, const char *arg)
{
	debug(LOG_DEBUG, "Argument: [%s] (@%x)", arg, arg);

    char *mac = (char *)arg;

    if (!is_mac_valid(mac)) {
        debug(LOG_ERR, "mac invalid");
        if(write(fd, "No", 2) == -1) {
			debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
        }
        return;
    }

	/* We get the node or return... */
	if (!client_list_is_exist(mac)) {
		debug(LOG_DEBUG, "Client not found.");
		if(write(fd, "No", 2) == -1) {
			debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
		}

		return;
	}

	/* deny.... */
	/* TODO: maybe just deleting the connection is not best... But this
	 * is a manual command, I don't anticipate it'll be that useful. */
	if (iptables_fw_deny_mac(mac)) {
        debug(LOG_DEBUG, "fail to deny Client.");
		if(write(fd, "No", 2) == -1) {
			debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
		}

		return;
	}

	if(write(fd, "Yes", 3) == -1) {
		debug(LOG_CRIT, "Unable to write Yes: %s", strerror(errno));
	}

	debug(LOG_DEBUG, "Exiting wdctl_reset...");
}

static void
wdctl_delete_client(int fd, const char *arg)
{
	debug(LOG_DEBUG, "Argument: [%s] (@%x)", arg, arg);

    char *mac = (char *)arg;

    if (!is_mac_valid(mac)) {
        debug(LOG_ERR, "mac invalid");
        if(write(fd, "No", 2) == -1) {
			debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
        }
        return;
    }

	/* We get the node or return... */
	if (!client_list_is_exist(mac)) {
		debug(LOG_DEBUG, "Client not found.");
		if(write(fd, "No", 2) == -1) {
			debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
		}

		return;
	}

	if (client_list_del(mac)) {
        debug(LOG_DEBUG, "fail to delete Client.");
		if(write(fd, "No", 2) == -1) {
			debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
		}

		return;
	}

	if(write(fd, "Yes", 3) == -1) {
		debug(LOG_CRIT, "Unable to write Yes: %s", strerror(errno));
	}

	debug(LOG_DEBUG, "Exiting wdctl_delete_client...");
}

static void wdctl_set_client(int fd, const char *arg)
{
    debug(LOG_DEBUG, "Argument: [%s] (@%x)", arg, arg);

    int rc;
    char mac[128] = {0};
    char config[128] = {0};
    char value[128] = {0};

    rc = sscanf(arg, "%s %s %s", mac, config, value);
    if (3 != rc) {
        debug(LOG_DEBUG, "fail to set Client.");
        if(write(fd, "No", 2) == -1) {
            debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
        }
        return;
    }
    debug(LOG_DEBUG, "get client mac %s config %s value %s", mac, config, value);

    if (!is_mac_valid(mac)) {
        debug(LOG_ERR, "mac invalid");
        if(write(fd, "No", 2) == -1) {
            debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
        }
        return;
    }

    /* We get the node or return... */
    if (!client_list_is_exist(mac)) {
        debug(LOG_DEBUG, "Client not found.");
        if(write(fd, "No", 2) == -1) {
            debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
        }

        return;
    }

    if (!strncasecmp(config, "auth", strlen("auth") + 1)) {
        if (atoi(value)) {
            client_list_set_auth(mac, 1);
        } else {
            client_list_set_auth(mac, 0);
        }
    } else if (!strncasecmp(config, "fw_state", strlen("fw_state") + 1)) {
        if (atoi(value)) {
            client_list_set_fw_state(mac, 1);
        } else {
            client_list_set_fw_state(mac, 0);
        }
    } else if (!strncasecmp(config, "ip", strlen("ip") + 1)) {
        client_list_set_ip(mac, value);
    } else if (!strncasecmp(config, "token", strlen("token") + 1)) {
        client_list_set_token(mac, value);
    } else if (!strncasecmp(config, "incoming", strlen("incoming") + 1)) {
        client_list_set_incoming(mac, atoi(value));
    } else if (!strncasecmp(config, "outgoing", strlen("outgoing") + 1)) {
        client_list_set_outgoing(mac, atoi(value));
    } else if (!strncasecmp(config, "last_updated", strlen("last_updated") + 1)) {
        client_list_set_last_updated(mac, atoi(value));
    } else if (!strncasecmp(config, "connect", strlen("connect") + 1)) {
        if (atoi(value)) {
            client_list_set_tracked(mac, CLIENT_TRACKED);
        } else {
            client_list_set_tracked(mac, CLIENT_UNTRACKED);
        }
    } else {
        debug(LOG_DEBUG, "unkown command.");
        if(write(fd, "No", 2) == -1) {
            debug(LOG_CRIT, "Unable to write No: %s", strerror(errno));
        }
    }

    if(write(fd, "Yes", 3) == -1) {
        debug(LOG_CRIT, "Unable to write Yes: %s", strerror(errno));
    }

    debug(LOG_DEBUG, "Exiting wdctl_set_client...");
}

