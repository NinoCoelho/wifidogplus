/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * appctl.c
 * Original Author : chenjunpei@jarxi.com, 2016-7-12.
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
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include "appctl.h"
#include "common.h"
#include "safe.h"


#define STATUS_BUF_SIZ	65536
#ifdef debug
#undef debug
#endif
#define debug(level, format, ...) fprintf (stderr, "%s:%s:%d: "format"\n", __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__)


static appctl_t config;

static void usage(void);
static void init_config(void);
static void parse_commandline(int, char **);
static int connect_to_server(const char *);
static size_t send_request(int, const char *);
static void ctl_status(void);
static void ctl_stop(void);
static void ctl_reset(void);
static void ctl_restart(void);
static void ctl_check(void);
static void ctl_appurl(char *buf);



static void
usage(void)
{
    printf("Usage: appctl [options] command [arguments]\n");
    printf("\n");
    printf("options:\n");
    printf("  -s <path>                 Path to the socket\n");
    printf("  -h                        Print usage\n");
    printf("\n");
    printf("commands:\n");
    printf("  status                    Obtain the status of soft\n");
    printf("  stop                      Stop the running soft\n");
    printf("  check                     Check if soft is running\n");
    printf("  print                     open print when soft is running\n");
    printf("  syslog                    open syslog when soft is running\n");
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
	config.command = CTL_UNDEF;
}

/** @internal
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void
parse_commandline(int argc, char **argv)
{
    static int optind = 1;
    int c;

#if 0
    while (-1 != (c = getopt(argc, argv, "s:h"))) {
        switch(c) {
            case 'h':
                usage();
                exit(1);
                break;

            case 's':
                if (optarg) {
		    careful_free(config.socket);
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
#endif

    if (strcmp(*(argv + optind), "status") == 0) {
	    config.command = CTL_STATUS;
    } else if (strcmp(*(argv + optind), "stop") == 0) {
	    config.command = CTL_STOP;
    } else if (strcmp(*(argv + optind), "check") == 0) {
	    config.command = CTL_CHECK;
    } else if (strcmp(*(argv + optind), "print") == 0) {
	    config.command = CTL_PRINT;
    } else if (strcmp(*(argv + optind), "syslog") == 0) {
	    config.command = CTL_SYSLOG;
    } else if (strcmp(*(argv + optind), "appurl") == 0) {
	    config.command = CTL_APPURL;
	    if ((argc - (optind + 1)) <= 0) {
		    fprintf(stderr, "appctl: Error: You must specify appid\n");
		    usage();
		    return;
	    }
	    config.param = strdup(*(argv + optind + 1));
    }
	 else {
	    fprintf(stderr, "ctl: Error: Invalid command \"%s\"\n", *(argv + optind));
	    usage();
	    return;
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
        return (1);
    }
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un,
			strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		fprintf(stderr, "ctl: the soft probably not started (Error: %s)\n", strerror(errno));
		return (1);
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
            fprintf(stderr, "Write failed: %s\n", strerror(errno));
            return (1);
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
                return (1);
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
            return (1);
        }
        else if (nfds < 0){
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            return (1);
        }
    }while (!done);
    buf[totalbytes] = '\0';
    // process the reponse
    debug(LOG_DEBUG, "HTTP Response from Server:[%s]", buf);
    return OK;
}

static void
ctl_status(void)
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
ctl_stop(void)
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

static void ctl_check(void)
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

static void ctl_print(void)
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

static void ctl_syslog(void)
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

static void ctl_appurl(char *buf)
{
    int sock;
    char    buffer[4096] = {0};
    char    request[64] = {0};
    size_t  len;

    sock = connect_to_server(config.socket);

    strncpy(request, "appurl ", strlen("appurl ") + 1);
    strncat(request, config.param, (64 - strlen(request)));
    strncat(request, "\r\n\r\n", (64 - strlen(request)));

    len = send_request(sock, request);

    if (OK == receive_response(sock, buffer, sizeof(buffer) / sizeof(buffer[0]))) {
        memcpy(buf, buffer, strlen(buffer));
    }

    shutdown(sock, 2);
    close(sock);
}



int
appctl_main(int argc, char **argv)
{
	/* Init configuration */
	init_config();
	parse_commandline(argc, argv);

	switch(config.command) {
	case CTL_STATUS:
		ctl_status();
		break;
	case CTL_STOP:
		ctl_stop();
		break;
    case CTL_CHECK:
        ctl_check();
        break;
    case CTL_PRINT:
        ctl_print();
        break;
    case CTL_SYSLOG:
        ctl_syslog();
        break;

	default:
		/* XXX NEVER REACHED */
		fprintf(stderr, "Oops\n");
		return (1);
		break;
	}
	return (0);
}

int
appctl_cmd(char *buf, char *pram)
{
    char cmd[128] = {0};
    char *appctl_argv[] = {"appctl", cmd};

    memcpy(cmd, pram, strlen(pram) + 1);

    /* Init configuration */
	init_config();
	parse_commandline(2, appctl_argv);

	switch(config.command) {
	case CTL_STATUS:
		ctl_status();
		break;
	case CTL_STOP:
		ctl_stop();
		break;
    case CTL_CHECK:
        ctl_check();
        break;
    case CTL_PRINT:
        ctl_print();
        break;
    case CTL_SYSLOG:
        ctl_syslog();
        break;

	default:
		/* XXX NEVER REACHED */
		fprintf(stderr, "Oops\n");
		return (1);
		break;
	}
	return (0);
}

int
appctl_appurl(char *buf, char *pram)
{
    char cmd[128] = {0};
    char *appctl_argv[] = {"appctl", "appurl", cmd};

    memcpy(cmd, pram, strlen(pram) + 1);

    /* Init configuration */
	init_config();
	parse_commandline(3, appctl_argv);

	switch(config.command) {
    case CTL_APPURL:
        ctl_appurl(buf);
        break;

	default:
		/* XXX NEVER REACHED */
		fprintf(stderr, "Oops\n");
		return (1);
		break;
	}
	return (0);
}

int appctl_test(void)
{
    printf("--------------------start\n");
    char *appctl_argv[] = {"appctl", "status"};
    //appctl_main(sizeof(appctl_argv) / sizeof(appctl_argv[0]), appctl_argv);
    static char buf[65536] = {0};
    //appctl_cmd(buf, "status");
    //appctl_cmd(buf, "client_record");
    appctl_appurl(buf, "240000481");
    printf("%s", buf);
    printf("--------------------end\n");
    return 0;
}

