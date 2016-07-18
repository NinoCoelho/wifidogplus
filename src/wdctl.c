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
/** @file wdctl.c
    @brief Monitoring and control of wifidog, client part
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
#include <errno.h>

#include "wdctl.h"
#include "common.h"


#define STATUS_BUF_SIZ	65536
#ifdef debug
#undef debug
#endif
#define debug(level, format, ...)// fprintf (stderr, "%s:%s:%d: "format"\n", __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__)


static s_config config;

static void usage(void);
static void init_config(void);
static void parse_commandline(int, char **);
static int connect_to_server(const char *);
static size_t send_request(int, const char *);
static void wdctl_status(void);
static void wdctl_stop(void);
static void wdctl_reset(void);
static void wdctl_restart(void);
static void wdctl_check(void);


/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wdctl is run with -h or with an unknown option
 */
static void
usage(void)
{
    printf("Usage: wdctl [options] command [arguments]\n");
    printf("\n");
    printf("options:\n");
    printf("  -s <path>                 Path to the socket\n");
    printf("  -h                        Print usage\n");
    printf("\n");
    printf("commands:\n");
    printf("  reset [mac]               Reset the specified mac connection\n");
    printf("  delete_client [mac]       Delete the specified client and reset connection\n");
    printf("  set_client [mac] [auth|fw_state...] [value] Set the specified client info\n");
    printf("  status                    Obtain the status of wifidog\n");
    printf("  stop                      Stop the running wifidog\n");
    printf("  restart                   Re-start the running wifidog (without disconnecting active users!)\n");
    printf("  check                     Check if wifidog is running\n");
    printf("  print                     open print when wifidog is running\n");
    printf("  syslog                    open syslog when wifidog is running\n");
    printf("\n");
}

/** @internal
 *
 * Init default values in config struct
 */
static void
init_config(void)
{

	config.socket = strdup(DEFAULT_SOCK);
	config.command = WDCTL_UNDEF;
}

/** @internal
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void
parse_commandline(int argc, char **argv)
{
    extern int optind;
    int c;

    while (-1 != (c = getopt(argc, argv, "s:h"))) {
        switch(c) {
            case 'h':
                usage();
                exit(1);
                break;

            case 's':
                if (optarg) {
		    free(config.socket);
		    config.socket = strdup(optarg);
                }
                break;

            default:
                usage();
                exit(1);
                break;
        }
    }

    if ((argc - optind) <= 0) {
	    usage();
	    exit(1);
    }

    if (strcmp(*(argv + optind), "status") == 0) {
	    config.command = WDCTL_STATUS;
    } else if (strcmp(*(argv + optind), "stop") == 0) {
	    config.command = WDCTL_STOP;
    } else if (strcmp(*(argv + optind), "reset") == 0) {
	    config.command = WDCTL_KILL;
	    if ((argc - (optind + 1)) <= 0) {
		    fprintf(stderr, "wdctl: Error: You must specify "
				    "a Mac address to reset\n");
		    usage();
		    exit(1);
	    }
	    config.param = strdup(*(argv + optind + 1));
    } else if (strcmp(*(argv + optind), "delete_client") == 0) {
	    config.command = WDCTL_DELETE_CLIENT;
	    if ((argc - (optind + 1)) <= 0) {
		    fprintf(stderr, "wdctl: Error: You must specify "
				    "a Mac address to delete\n");
		    usage();
		    exit(1);
	    }
	    config.param = strdup(*(argv + optind + 1));
    } else if (strcmp(*(argv + optind), "set_client") == 0) {
        if (argc < 5) {
            fprintf(stderr, "wdctl: Error, usge: wdctl set_client [mac] [config] [value]\n");
            return;
        }
	    config.command = WDCTL_SET_CLIENT;
	    if ((argc - (optind + 1)) <= 0) {
		    fprintf(stderr, "wdctl: Error: You must specify "
				    "a Mac address to set\n");
		    usage();
		    exit(1);
	    }
	    config.param = strdup(*(argv + optind + 1));
        config.config = strdup(*(argv + optind + 2));
        config.value = strdup(*(argv + optind + 3));
    } else if (strcmp(*(argv + optind), "restart") == 0) {
	    config.command = WDCTL_RESTART;
    } else if (strcmp(*(argv + optind), "check") == 0) {
	    config.command = WDCTL_CHECK;
    } else if (strcmp(*(argv + optind), "print") == 0) {
	    config.command = WDCTL_PRINT;
    } else if (strcmp(*(argv + optind), "syslog") == 0) {
	    config.command = WDCTL_SYSLOG;
    }
	 else {
	    fprintf(stderr, "wdctl: Error: Invalid command \"%s\"\n", *(argv + optind));
	    usage();
	    exit(1);
    }
}

static int
connect_to_server(const char *sock_name)
{
	int sock;
	struct sockaddr_un	sa_un;

	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        exit(1);
    }
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un,
			strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		fprintf(stderr, "wdctl: wifidog probably not started (Error: %s)\n", strerror(errno));
		exit(1);
	}

	return sock;
}

static size_t
send_request(int sock, const char *request)
{
	size_t	len;
    ssize_t written;

    len = 0;
    while (len != strlen(request)) {
        written = write(sock, (request + len), strlen(request) - len);
        if (written == -1) {
            fprintf(stderr, "Write to wifidog failed: %s\n", strerror(errno));
            exit(1);
        }
        len += (size_t) written;
    }

	return len;
}

static int receive_response(int sockfd, char *buf, size_t buf_size)
{
    int nfds, done;
    ssize_t numbytes;
    size_t    totalbytes;
    fd_set  readfds;
    struct timeval  timeout;

    numbytes = totalbytes = 0;
    done =0;
    do
    {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        nfds = sockfd + 1;

        nfds = select(nfds, &readfds, NULL, NULL, &timeout);

        if (nfds > 0)
        {
            /** We don't have to use FD_ISSET() because there
             *  was only one fd. */
            numbytes = read(sockfd, buf + totalbytes, buf_size - (totalbytes + 1));
            if (numbytes < 0)
            {
                debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
                exit(1);
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
            exit(1);
        }
        else if (nfds < 0){
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            exit(1);
        }
    }while (!done);
    buf[totalbytes] = '\0';
    // process the reponse
    debug(LOG_DEBUG, "HTTP Response from Server:[%s]", buf);
    return OK;
}

static void
wdctl_status(void)
{
	int	sock;
	char	buffer[STATUS_BUF_SIZ] = {0};
	char	request[16] = {0};
    ssize_t len;

	sock = connect_to_server(config.socket);

	strncpy(request, "status\r\n\r\n", strlen("status\r\n\r\n") + 1);

	len = send_request(sock, request);

	if (OK == receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

static void
wdctl_stop(void)
{
	int	sock;
	char	buffer[4096] = {0};
	char	request[16] = {0};
    ssize_t len;

	sock = connect_to_server(config.socket);

	strncpy(request, "stop\r\n\r\n", strlen("stop\r\n\r\n") + 1);

	len = send_request(sock, request);

    if (OK == receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

void
wdctl_reset(void)
{
	int	sock;
	char	buffer[4096] = {0};
	char	request[64] = {0};
	size_t	len;
    ssize_t rlen;

	sock = connect_to_server(config.socket);

	strncpy(request, "reset ", strlen("reset ") + 1);
	strncat(request, config.param, (64 - strlen(request)));
	strncat(request, "\r\n\r\n", (64 - strlen(request)));

	len = send_request(sock, request);

    if (OK != receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        shutdown(sock, 2);
        close(sock);
        return;
	}

	if (strcmp(buffer, "Yes") == 0) {
		printf("Connection %s successfully reset.\n", config.param);
	} else if (strcmp(buffer, "No") == 0) {
		printf("Connection %s was not active.\n", config.param);
	} else {
		fprintf(stderr, "wdctl: Error: WiFiDog sent an abnormal "
				"reply.\n");
	}

	shutdown(sock, 2);
	close(sock);
}

static void
wdctl_restart(void)
{
	int	sock;
	char	buffer[4096] = {0};
	char	request[16] = {0};
    ssize_t len;

	sock = connect_to_server(config.socket);

	strncpy(request, "restart\r\n\r\n", strlen("restart\r\n\r\n") + 1);

	len = send_request(sock, request);

	if (OK == receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

static void wdctl_delete_client(void)
{
    int sock;
    char    buffer[4096] = {0};
    char    request[64] = {0};
    size_t  len;
    int rlen;

    sock = connect_to_server(config.socket);

    strncpy(request, "delete_client ", strlen("delete_client ") + 1);
    strncat(request, config.param, (64 - strlen(request)));
    strncat(request, "\r\n\r\n", (64 - strlen(request)));

    len = send_request(sock, request);

    if (OK != receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        shutdown(sock, 2);
        close(sock);
        return;
    }

    if (strcmp(buffer, "Yes") == 0) {
        printf("Connection %s successfully delete client.\n", config.param);
    } else if (strcmp(buffer, "No") == 0) {
        printf("Connection %s was not active.\n", config.param);
    } else {
        fprintf(stderr, "wdctl: Error: WiFiDog sent an abnormal "
                "reply.\n");
    }

    shutdown(sock, 2);
    close(sock);
}

static void wdctl_check(void)
{
    int	sock;
	char	buffer[STATUS_BUF_SIZ] = {0};
	char	request[16] = {0};
    ssize_t len;

	sock = connect_to_server(config.socket);

	strncpy(request, "check\r\n\r\n", strlen("check\r\n\r\n") + 1);

	len = send_request(sock, request);

	if (OK == receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

static void wdctl_print(void)
{
    int	sock;
	char	buffer[STATUS_BUF_SIZ] = {0};
	char	request[16] = {0};
    ssize_t len;

	sock = connect_to_server(config.socket);

	strncpy(request, "print\r\n\r\n", strlen("print\r\n\r\n") + 1);

	len = send_request(sock, request);

	if (OK == receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

static void wdctl_syslog(void)
{
    int	sock;
	char	buffer[STATUS_BUF_SIZ] = {0};
	char	request[16] = {0};
    ssize_t len;

	sock = connect_to_server(config.socket);

	strncpy(request, "syslog\r\n\r\n", strlen("syslog\r\n\r\n") + 1);

	len = send_request(sock, request);

	if (OK == receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

static void wdctl_set_client(void)
{
    int sock;
    char    buffer[4096] = {0};
    char    request[64] = {0};
    size_t  len;
    int rlen;

    sock = connect_to_server(config.socket);

    strncpy(request, "set_client ", strlen("set_client ") + 1);
    strncat(request, config.param, (64 - strlen(request)));
    strncat(request, " ", (64 - strlen(request)));
    strncat(request, config.config, (64 - strlen(request)));
    strncat(request, " ", (64 - strlen(request)));
    strncat(request, config.value, (64 - strlen(request)));
    strncat(request, "\r\n\r\n", (64 - strlen(request)));

    len = send_request(sock, request);

    if (OK != receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        shutdown(sock, 2);
        close(sock);
        return;
    }

    if (strcmp(buffer, "Yes") == 0) {
        printf("Connection %s successfully set client.\n", config.param);
    } else if (strcmp(buffer, "No") == 0) {
        printf("Connection %s was not active.\n", config.param);
    } else {
        fprintf(stderr, "wdctl: Error: WiFiDog sent an abnormal "
                "reply.\n");
    }

    shutdown(sock, 2);
    close(sock);
}

int
main(int argc, char **argv)
{

	/* Init configuration */
	init_config();
	parse_commandline(argc, argv);

	switch(config.command) {
	case WDCTL_STATUS:
		wdctl_status();
		break;

	case WDCTL_STOP:
		wdctl_stop();
		break;

	case WDCTL_KILL:
		wdctl_reset();
		break;

	case WDCTL_RESTART:
		wdctl_restart();
		break;
    case WDCTL_DELETE_CLIENT:
        wdctl_delete_client();
        break;
    case WDCTL_SET_CLIENT:
        wdctl_set_client();
        break;
    case WDCTL_CHECK:
        wdctl_check();
        break;
    case WDCTL_PRINT:
        wdctl_print();
        break;
    case WDCTL_SYSLOG:
        wdctl_syslog();
        break;


	default:
		/* XXX NEVER REACHED */
		fprintf(stderr, "Oops\n");
		exit(1);
		break;
	}
	exit(0);
}

