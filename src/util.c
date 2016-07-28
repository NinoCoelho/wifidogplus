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
/**
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2006 Benoit Gr茅goire <bock@step.polymtl.ca>
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
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdarg.h>

#if defined(__NetBSD__)
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <util.h>
#endif

#ifdef __linux__
#include <netinet/in.h>
#include <net/if.h>
#endif

#include <string.h>
#include <pthread.h>
#include <netdb.h>
#include "common.h"
#include "client_list.h"
#include "safe.h"
#include "util.h"
#include "conf.h"
#include "debug.h"
#include "../config.h"
#include "watchdog.h"

#ifdef __OPENWRT__
#include <uci_config.h>
#include <uci.h>
#endif

#include <curl/curl.h>
#include <json/json.h>

static int execute(const char *cmd_line, int quiet);


#define YDCQ_INFO_CONFIG_FILE "/etc/config/1dcq_info"
static system_info_t __system_info;
static pthread_mutex_t get_system_info_mutex = PTHREAD_MUTEX_INITIALIZER;

extern fw_init_flag;
extern fw_rebuild_flag;
extern pthread_mutex_t fw_init_mutex;

static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t exec_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Defined in ping_thread.c */
extern time_t started_time;

/* Defined in commandline.c */
extern pid_t restart_orig_pid;

/* XXX Do these need to be locked ? */
static time_t last_online_time = 0;
static time_t last_offline_time = 0;
static time_t last_auth_online_time = 0;
static time_t last_auth_offline_time = 0;
static time_t last_appserv_online_time = 0;
static time_t last_appserv_offline_time = 0;

unsigned long tracked_clients_num = 0;

#define CMDBUF_LENGTH 512
int do_execute(char *fmt, ...)
{
    va_list        vargs;
    int            rc = 0;
    char  CmdBuf[CMDBUF_LENGTH] = {0};

    memset(CmdBuf,0,sizeof(CmdBuf));
    va_start(vargs, fmt);
    rc = vsnprintf(CmdBuf, CMDBUF_LENGTH, fmt, vargs);
    va_end(vargs);

    debug(LOG_DEBUG, "doing command %s", CmdBuf);
    rc = execute_cmd(CmdBuf, NULL);

    return rc;
}

void getKeyvalue(char *buf, char *reponse,char *key){
    char *tmp = NULL;
    tmp=strstr(reponse,key)+(strlen(key));
    if (tmp) {
        sscanf(tmp,"%[^\r\n]",buf);
    }
}

int getInterface_cmd(char *buf,char *cmd,...){
	va_list 	   vargs;
	char  CmdBuf[CMDBUF_LENGTH]={0};
    char popen_buf[POPEN_MAX_BUF]={0};

	va_start(vargs, cmd);
	vsnprintf(CmdBuf, CMDBUF_LENGTH, cmd, vargs);
	va_end(vargs);

    if(execute_cmd(CmdBuf, popen_buf)){
        debug(LOG_ERR, "====Failed to perform the [%s] command!!!===",CmdBuf);
        return -1;
    } else {
        //debug(LOG_DEBUG, " %s:%s:[%s]",__func__,CmdBuf,popen_buf);
        sscanf(popen_buf,"%[^\r\n]",buf);
    }
    return 0;
}

/* return: valid 1, invalid 0 */
int is_mac_valid(const void *mac)
{
    char *str = (char *)mac;
	int i;
    int len;

    len = strlen(str);

	if(len != 17)
    {
		return 0;
    }

	for(i=0; i<5; i++)
    {
		if((!isxdigit( str[i*3]))
            || (!isxdigit( str[i*3+1]))
            || (str[i*3+2] != ':'))
        {
			return 0;
        }
	}
	return (isxdigit(str[15]) && isxdigit(str[16])) ? 1: 0;
}

int is_ip_valid(const char *str)
{
    struct in_addr addr;    // for examination

    if (!str) {
        return 0;
    }

    if( (! strcmp("any", str)) || (! strcmp("any/0", str))) {
        return 1;
    }

    if(! (inet_aton(str, &addr))){
        fprintf(stderr, "%s: %s is not a valid IP address.\n", __func__, str);
        return 0;
    }

    return 1;
}

static int execute_popen(const char *cmd, char *result) // a bug here using mtk sdk 4200 xxxc
{
   char buf_ps[POPEN_MAX_BUF]={0};
   char ps[MAX_BUF]={0};
   FILE *ptr;
   strcpy(ps, cmd);

   if((ptr=popen(ps, "r"))!=NULL)
   {
        if (result) {
            while(!feof(ptr) && fgets(buf_ps, POPEN_MAX_BUF, ptr)!=NULL)
            {
               strcat(result, buf_ps);
               if(strlen(result)>POPEN_MAX_BUF) {
                   break;
               }
            }
        }
        pclose(ptr);
        ptr = NULL;
        return 0;
    }
    else
    {
        debug(LOG_ERR, "popen %s error\n", ps);
        return -1;
    }

    return -1;
}

int execute_cmd(const char *cmd, char *result_buf)
{
    int ret;

    if (!cmd) {
        debug(LOG_ERR, "the cmd should not be NULL");
        return -1;
    }

#ifdef __OPENWRT__
    pthread_mutex_lock(&exec_mutex);
    if (!result_buf) {
        ret = execute(cmd, 0);
    } else {
        ret = execute_popen(cmd, result_buf);
    }
    pthread_mutex_unlock(&exec_mutex);
#endif
#ifdef __MTK_SDK__
    /* xxx: in mtk sdk, execute and execute_popen work bad, fork progress may not exit.
     * can not using mutex.
     * And must have measures deal with error when calling exec function.
     */
    if (!result_buf) {
        //ret = system(cmd);
        pthread_mutex_lock(&exec_mutex);
        ret = COMM_RunCommandWithTimeout(10, cmd);
        pthread_mutex_unlock(&exec_mutex);
    } else {
        ret = execute_popen(cmd, result_buf);
    }
#endif

    return ret;
}

/** Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
static int
execute(const char *cmd_line, int quiet)
{
        int pid,
            status,
            rc;

        const char *new_argv[4];
        new_argv[0] = "/bin/sh";
        new_argv[1] = "-c";
        new_argv[2] = cmd_line;
        new_argv[3] = NULL;

        pid = safe_fork();
        if (pid == 0) {    /* for the child process:         */
                /* We don't want to see any errors if quiet flag is on */
                if (quiet) {
                    close(2);
                }
                if (execvp("/bin/sh", (char *const *)new_argv) == -1) {    /* execute the command  */
                        debug(LOG_ERR, "execvp(): %s", strerror(errno));
                } else {
                        debug(LOG_ERR, "execvp() failed");
                }
                exit(1);
        }

        /* for the parent:      */
	debug(LOG_DEBUG, "Waiting for PID %d to exit", pid);
	rc = waitpid(pid, &status, 0);
	debug(LOG_DEBUG, "Process PID %d exited", rc);

    return (WEXITSTATUS(status));
}

int
execute_not_care(const char *cmd_line, int quiet)
{
        int pid,
            status,
            rc;

        if (!cmd_line) {
            debug(LOG_ERR, "the cmd should not be NULL");
            return -1;
        }

        const char *new_argv[4];
        new_argv[0] = "/bin/sh";
        new_argv[1] = "-c";
        new_argv[2] = cmd_line;
        new_argv[3] = NULL;

        pid = safe_fork();
        if (pid == 0) {    /* for the child process:         */
                /* We don't want to see any errors if quiet flag is on */
                if (quiet) {
                    close(2);
                }
                if (execvp("/bin/sh", (char *const *)new_argv) == -1) {    /* execute the command  */
                        debug(LOG_ERR, "execvp(): %s", strerror(errno));
                } else {
                        debug(LOG_ERR, "execvp() failed");
                }
                exit(1);
        }

        /* for the parent:      */
    usleep(1000);
    return 0;
}

static uint64_t COMM_GetTime( void )
{
	uint64_t micro;
	struct timeval curtime;

	gettimeofday(&curtime, NULL);

	micro = curtime.tv_sec;
	micro *= 1000000LL;
	micro += curtime.tv_usec;

	//return micro seconds
	return micro;
}

static int COMM_WaitTime(uint64_t MilliSec, uint64_t start)
{
	if (COMM_GetTime() - start >= MilliSec * 1000)
		return 1; // 1 = ok

	return 0; // not yet... still wait
}

int COMM_RunCommandWithTimeout(int timeout/* SECOND */, const char *command)
{
    pid_t pid = -1;
    uint64_t StartTime;
    int ret, status = 0, is_timeout = 0;

    pid = fork();
    switch(pid) {
        case -1: return -1;

        case 0:
            execl("/bin/sh", "sh", "-c", command, (char *)0);
            _exit(0);
        break;

        default:
            StartTime = COMM_GetTime();
            do {
                usleep(100000);
                ret = waitpid(pid, &status, WNOHANG);
                if( COMM_WaitTime( timeout * 1000, StartTime ) ){
                    is_timeout = 1;
                    break;
                }
            }while( !ret );

            if( is_timeout == 0 ) {
                if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                    debug(LOG_DEBUG, "RUN '%s' FAILED!", command);
                    return -1;
                }

                debug(LOG_DEBUG, "RUN '%s' SUCCESS!", command);
                return 0;
            }
            else {
                kill(pid, SIGKILL);
                waitpid(pid, NULL, WNOHANG);

                debug(LOG_DEBUG, "RUN '%s' TIMEOUT!", command);
                return -1;
            }
        break;
    }
}

	struct in_addr *
wd_gethostbyname(const char *name)
{
	struct hostent *he;
	struct in_addr *h_addr, *in_addr_temp;

	/* XXX Calling function is reponsible for free() */

	h_addr = safe_malloc(sizeof(struct in_addr));

	LOCK_GHBN();

	he = gethostbyname(name);

	if (he == NULL) {
		free(h_addr);
		UNLOCK_GHBN();
		return NULL;
	}

	mark_online();

	in_addr_temp = (struct in_addr *)he->h_addr_list[0];
	h_addr->s_addr = in_addr_temp->s_addr;

	UNLOCK_GHBN();

	return h_addr;
}

	char *
get_iface_ip(const char *ifname)
{
#if defined(__linux__)
	struct ifreq if_data;
	struct in_addr in;
	char *ip_str;
	int sockd;
	u_int32_t ip;

	/* Create a socket */
	if ((sockd = socket (AF_INET, SOCK_PACKET, htons(0x8086))) < 0) {
		debug(LOG_ERR, "socket(): %s", strerror(errno));
		return NULL;
	}

	/* Get IP of internal interface */
	strcpy (if_data.ifr_name, ifname);

	/* Get the IP address */
	if (ioctl (sockd, SIOCGIFADDR, &if_data) < 0) {
		debug(LOG_ERR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
		return NULL;
	}
	memcpy ((void *) &ip, (void *) &if_data.ifr_addr.sa_data + 2, 4);
	in.s_addr = ip;

	ip_str = safe_strdup(inet_ntoa(in));
	close(sockd);

	return ip_str;
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	char *str = NULL;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	/* XXX arbitrarily pick the first IPv4 address */
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_INET)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "%s: no IPv4 address assigned");
		goto out;
	}
	str = safe_strdup(inet_ntoa(
				((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
out:
	freeifaddrs(ifap);
	return str;
#else
	return safe_strdup(DUMY_IP);
#endif
}

	char *
get_iface_mac(const char *ifname)
{
#if defined(__linux__)
	int r, s;
	struct ifreq ifr;
	char *hwaddr, mac[13];

	strcpy(ifr.ifr_name, ifname);

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
		return NULL;
	}

	r = ioctl(s, SIOCGIFHWADDR, &ifr);
	if (r == -1) {
		debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
		close(s);
		return NULL;
	}

	hwaddr = ifr.ifr_hwaddr.sa_data;
	close(s);
	snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
			hwaddr[0] & 0xFF,
			hwaddr[1] & 0xFF,
			hwaddr[2] & 0xFF,
			hwaddr[3] & 0xFF,
			hwaddr[4] & 0xFF,
			hwaddr[5] & 0xFF
		);

	return safe_strdup(mac);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	const char *hwaddr;
	char mac[13], *str = NULL;
	struct sockaddr_dl *sdl;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_LINK)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "%s: no link-layer address assigned");
		goto out;
	}
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	hwaddr = LLADDR(sdl);
	snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
			hwaddr[0] & 0xFF, hwaddr[1] & 0xFF,
			hwaddr[2] & 0xFF, hwaddr[3] & 0xFF,
			hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

	str = safe_strdup(mac);
out:
	freeifaddrs(ifap);
	return str;
#else
	return NULL;
#endif
}

	char *
get_gw_mac(const char *ifname)
{
#if defined(__linux__)
	int r, s;
	struct ifreq ifr;
	char *hwaddr, mac[18];

	strcpy(ifr.ifr_name, ifname);

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		debug(LOG_ERR, "get_gw_mac socket: %s", strerror(errno));
		return NULL;
	}

	r = ioctl(s, SIOCGIFHWADDR, &ifr);
	if (r == -1) {
		debug(LOG_ERR, "get_gw_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
		close(s);
		return NULL;
	}

	hwaddr = ifr.ifr_hwaddr.sa_data;
	close(s);
	snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			hwaddr[0] & 0xFF,
			hwaddr[1] & 0xFF,
			hwaddr[2] & 0xFF,
			hwaddr[3] & 0xFF,
			hwaddr[4] & 0xFF,
			hwaddr[5] & 0xFF
		);

	return safe_strdup(mac);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	const char *hwaddr;
	char mac[18], *str = NULL;
	struct sockaddr_dl *sdl;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_LINK)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "%s: no link-layer address assigned");
		goto out;
	}
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	hwaddr = LLADDR(sdl);
	snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			hwaddr[0] & 0xFF, hwaddr[1] & 0xFF,
			hwaddr[2] & 0xFF, hwaddr[3] & 0xFF,
			hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

	str = safe_strdup(mac);
out:
	freeifaddrs(ifap);
	return str;
#else
	return NULL;
#endif
}

	char *
get_ext_iface(void)
{
#ifdef __linux__
	FILE *input;
	char *device, *gw;
	int i = 1;
	int keep_detecting = 1;
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	device = (char *)safe_malloc(16);
	gw = (char *)safe_malloc(16);
	debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
	while(keep_detecting) {
		input = fopen("/proc/net/route", "r");
		while (!feof(input)) {
			/* XXX scanf(3) is unsafe, risks overrun */
			if ((fscanf(input, "%s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw) == 2) && strcmp(gw, "00000000") == 0) {
				careful_free(gw);
				debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after try %d", device, i);
				return device;
			}
		}
		fclose(input);
		debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after try %d (maybe the interface is not up yet?).  Retry limit: %d", i, NUM_EXT_INTERFACE_DETECT_RETRY);
		/* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
		timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
		timeout.tv_nsec = 0;
		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
		//for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
		if (NUM_EXT_INTERFACE_DETECT_RETRY != 0 && i>NUM_EXT_INTERFACE_DETECT_RETRY) {
			keep_detecting = 0;
		}
		i++;
	}
	debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", i - 1);
	/* exit(1); */
	careful_free(device);
	careful_free(gw);
#endif
	return NULL;
}

/*
 * arguments: ifname  - interface name
 *            if_addr - a 18-byte buffer to store mac address
 * description: fetch mac address according to given interface name
 */
int getIfMac(char *ifname, char *if_hw)
{
    struct ifreq ifr;
    char *ptr;
    int skfd;

    if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        debug(LOG_ERR, "getIfMac: open socket error");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
    if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(skfd);
        //error(E_L, E_LOG, T("getIfMac: ioctl SIOCGIFHWADDR error for %s"), ifname);
        return -1;
    }

    ptr = (char *)&ifr.ifr_addr.sa_data;
    sprintf(if_hw, "%02X:%02X:%02X:%02X:%02X:%02X",
            (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
            (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

    close(skfd);
    return 0;
}


	void mark_online() {
		int before;
		int after;

		before = is_online();
		time(&last_online_time);
		after = is_online();

		if (before != after) {
			debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
		}

	}

	void mark_offline() {
		int before;
		int after;

		before = is_online();
		time(&last_offline_time);
		after = is_online();

		if (before != after) {
			debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
		}

		/* If we're offline it definately means the auth server is offline */
		mark_auth_offline();

	}

	int is_online() {
		if (last_online_time == 0 || (last_offline_time - last_online_time) >= (config_get_config()->checkinterval * 2) ) {
			/* We're probably offline */
			return (0);
		}
		else {
			/* We're probably online */
			return (1);
		}
	}

	void mark_auth_online() {
		int before;
		int after;

		before = is_auth_online();
		time(&last_auth_online_time);
		after = is_auth_online();

		if (before != after) {
			debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
		}

#ifdef OFFLINE_CLEAR_FW
        pthread_mutex_lock(&fw_init_mutex);
        if (!fw_init_flag) {
            fw_rebuild_flag = 1;
            fw_init();
            fw_rebuild_flag = 0;
            fw_init_flag = 1;
        }
        pthread_mutex_unlock(&fw_init_mutex);
#endif

		/* If auth server is online it means we're definately online */
		mark_online();

	}

	void mark_auth_offline() {
		int before;
		int after;

		before = is_auth_online();
		time(&last_auth_offline_time);
		after = is_auth_online();

		if (before != after) {
			debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
		}

#ifdef OFFLINE_CLEAR_FW
        pthread_mutex_lock(&fw_init_mutex);
        if (fw_init_flag) {
            fw_destroy();
            fw_init_flag = 0;
        }
        pthread_mutex_unlock(&fw_init_mutex);
#endif
	}

	int is_auth_online() {
		if (!is_online()) {
			/* If we're not online auth is definately not online :) */
			return (0);
		}
		else if (last_auth_online_time == 0 || (last_auth_offline_time - last_auth_online_time) >= (config_get_config()->checkinterval * 2) ) {
			/* Auth is  probably offline */
			return (0);
		}
		else {
			/* Auth is probably online */
			return (1);
		}
	}

    /* cjpthree@126.com 2015.5.13 start */
	void mark_appserv_online() {
		int before;
		int after;

		before = is_appserv_online();
		time(&last_appserv_online_time);
		after = is_appserv_online();

		if (before != after) {
			debug(LOG_INFO, "APP_ONLINE status became %s", (after ? "ON" : "OFF"));
		}

		/* If app server is online it means we're definately online */
		mark_online();
	}

	void mark_appserv_offline() {
		int before;
		int after;

		before = is_appserv_online();
		time(&last_appserv_offline_time);
		after = is_appserv_online();

		if (before != after) {
			debug(LOG_INFO, "APP_ONLINE status became %s", (after ? "ON" : "OFF"));
		}

	}

	int is_appserv_online() {
		if (!is_online()) {
			/* If we're not online appserv is definately not online :) */
			return (0);
		}
		else if (last_auth_online_time == 0 || (last_appserv_offline_time - last_appserv_online_time) >= (config_get_config()->checkinterval * 2) ) {
			/* appserv is  probably offline */
			return (0);
		}
		else {
			/* appserv is probably online */
			return (1);
		}
	}
    /* cjpthree@126.com 2015.5.13 end */


/*
 * @return A string containing human-readable status text. MUST BE free()d by caller
 */
char * get_status_text() {
	char buffer[STATUS_BUF_SIZ];
	ssize_t len;
	s_config *config;
	t_auth_serv *auth_server;
	int		count;
	unsigned long int uptime = 0;
	unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;
	t_trusted_mac *p;
    struct tm *ptr;

	len = 0;

	uptime = time(NULL) - started_time;
	days    = uptime / (24 * 60 * 60);
	uptime -= days * (24 * 60 * 60);
	hours   = uptime / (60 * 60);
	uptime -= hours * (60 * 60);
	minutes = uptime / 60;
	uptime -= minutes * 60;
	seconds = uptime;

	snprintf((buffer + len), (sizeof(buffer) - len), "Version: " VERSION "\n");
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Uptime: %ud %uh %um %us\n", days, hours, minutes, seconds);
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Has been restarted: ");
	len = strlen(buffer);
	if (restart_orig_pid) {
		snprintf((buffer + len), (sizeof(buffer) - len), "yes (from PID %d)\n", restart_orig_pid);
		len = strlen(buffer);
	}
	else {
		snprintf((buffer + len), (sizeof(buffer) - len), "no\n");
		len = strlen(buffer);
	}

	snprintf((buffer + len), (sizeof(buffer) - len), "Internet Connectivity: %s\n", (is_online() ? "yes" : "no"));
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Auth server reachable: %s\n", (is_auth_online() ? "yes" : "no"));
	len = strlen(buffer);

    list_head_t *pos;
    client_hold_t *tpos;
    list_head_t traverse_list = LIST_HEAD_INIT(traverse_list);
    char time_buf[28] = {0};
    client_list_hold_t hold;
    unsigned int remain_time = 0;
    unsigned int d = 0;
    unsigned int h = 0;
    unsigned int m = 0;

    hold.head = &traverse_list;
    hold.func = NULL;
    hold.args = NULL;
    if (client_list_traverse((CLIENT_LIST_CONDITION_FUNC)client_list_hold, &hold)) {
        client_list_destory_hold(&hold);
        debug(LOG_ERR, "fail to create client_traverse_list");
    }

    count = 0;
    list_for_each(pos, &traverse_list) {
        tpos = list_entry(pos, client_hold_t, list);
        if (client_list_is_connect_really(tpos->client.mac)) {
            count++;
        }
    }
	snprintf((buffer + len), (sizeof(buffer) - len),
        "Clients served this session: %d\n", client_list_get_num());
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Clients tracked: %lu\n", tracked_clients_num);
	len = strlen(buffer);

    snprintf((buffer + len), (sizeof(buffer) - len),
        "Clients connect really: %d\n\n", count);
    len = strlen(buffer);

	count = 0;
	list_for_each(pos, &traverse_list) {
        tpos = list_entry(pos, client_hold_t, list);
		snprintf((buffer + len), (sizeof(buffer) - len), "Client %d\n", count + 1);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len),
            "  IP:\t\t%s\n", tpos->client.ip);
		len = strlen(buffer);

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  MAC:\t\t%s\n", tpos->client.mac);
		len = strlen(buffer);

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Auth:\t\t%d\n", tpos->client.auth);
		len = strlen(buffer);

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Token:\t%s\n", tpos->client.token);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len),
            "  Openid:\t%s\n", tpos->client.openid);
		len = strlen(buffer);

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Fw_state:\t%u\n", tpos->client.fw_state);
		len = strlen(buffer);

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Tracked:\t%u\n", tpos->client.tracked);
		len = strlen(buffer);

        ptr = localtime(&tpos->client.allow_time);
        sprintf(time_buf, "%d/%d/%d/%d:%d:%d",
            ptr->tm_year+1900, ptr->tm_mon+1, ptr->tm_mday,
            ptr->tm_hour, ptr->tm_min, ptr->tm_sec);
		snprintf((buffer + len), (sizeof(buffer) - len),
            "  AllowTime:\t%s\n", time_buf);
		len = strlen(buffer);

        (void)client_list_get_remain_allow_time(tpos->client.mac, &remain_time);
        d = remain_time / (24*60*60); remain_time %= (24*60*60);
		h = remain_time / (60*60); remain_time %= (60*60);
		m = remain_time / 60; remain_time %= 60;
        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Remain_time:\t%u d %u h %u m\n", d, h, m);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len),
            "  Incoming:\t%llu\n", tpos->client.counters.incoming);
		len = strlen(buffer);

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Outgoing:\t%llu\n", tpos->client.counters.outgoing);
		len = strlen(buffer);

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Up_limit:\t%u\n", tpos->client.counters.uplink_limit);
		len = strlen(buffer);

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Down_limit:\t%u\n", tpos->client.counters.downlink_limit);
		len = strlen(buffer);


        ptr = localtime(&tpos->client.counters.last_updated);
        sprintf(time_buf, "%d/%d/%d/%d:%d:%d",
            ptr->tm_year+1900, ptr->tm_mon+1, ptr->tm_mday,
            ptr->tm_hour, ptr->tm_min, ptr->tm_sec);
        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Last_updated:\t%s(Connect: %d)\n",
            time_buf, client_list_is_connect_really(tpos->client.mac));
		len = strlen(buffer);

#if ANTI_DOS
        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Dos_count:\t%u\n", tpos->client.dos_count);
		len = strlen(buffer);
#endif

        snprintf((buffer + len), (sizeof(buffer) - len),
            "  Host_name:\t%s\n", tpos->client.hostname);
		len = strlen(buffer);

		count++;
	}

    client_list_destory_hold(&hold);

	config = config_get_config();

	if (config->trustedmaclist != NULL) {
		snprintf((buffer + len), (sizeof(buffer) - len), "\nTrusted MAC addresses:\n");
		len = strlen(buffer);

		for (p = config->trustedmaclist; p != NULL; p = p->next) {
			snprintf((buffer + len), (sizeof(buffer) - len), "  %s\n", p->mac);
			len = strlen(buffer);
		}
	}
	snprintf((buffer + len), (sizeof(buffer) - len), "\nAuthentication servers:\n");
	len = strlen(buffer);

    /* if delete lock, can only support one server, and can not change on runtime */
    LOCK_CONFIG();
	for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
		snprintf((buffer + len), (sizeof(buffer) - len), "  Host: %s (%s)\n", auth_server->authserv_hostname, auth_server->last_ip);
		len = strlen(buffer);
	}
    UNLOCK_CONFIG();

	return safe_strdup(buffer);
}

static inline int goahead_list_condition(const client_t *client, _IN void *args)
{
    if (!client) {
        return 0;
    }

    if (client->auth < CLIENT_CONFIG
        && client_is_connect_really_free_lock(client)) {
        return 1;
    } else {
        return 0;
    }
}

char * get_status_text_goahead() {
	char buffer[STATUS_BUF_SIZ];
	ssize_t len = 0;
    list_head_t *pos;
    client_hold_t *tpos;
    list_head_t traverse_list = LIST_HEAD_INIT(traverse_list);
    client_list_hold_t hold;
    unsigned int remain_time = 0;

    hold.head = &traverse_list;
    hold.func = goahead_list_condition;
    hold.args = NULL;
    if (client_list_traverse((CLIENT_LIST_CONDITION_FUNC)client_list_hold, &hold)) {
        client_list_destory_hold(&hold);
        debug(LOG_ERR, "fail to create client_traverse_list");
    }

	list_for_each(pos, &traverse_list) {
        tpos = list_entry(pos, client_hold_t, list);

        (void)client_list_get_remain_allow_time(tpos->client.mac, &remain_time);
		snprintf((buffer + len), (sizeof(buffer) - len),
		"%s %s %s %d %u\n",
	    tpos->client.hostname,
	    tpos->client.ip,
	    tpos->client.mac,
	    (tpos->client.auth > CLIENT_CHAOS) ? 1 : 0,
	    remain_time + (config_get_config()->checkinterval / 2)); /* error litter than checkinterval */
	    len = strlen(buffer);
	}

    client_list_destory_hold(&hold);
	return safe_strdup(buffer);
}

#ifdef __OPENWRT__ // xxxc
static int get_1dcq_system_info()
{
    struct uci_package * pkg = NULL;
    struct uci_element *e;
    const char *value;
    struct uci_context * ctx = NULL; //定义一个UCI上下文的静态变量.
    int error_flag = 0;

    ctx = uci_alloc_context(); // 申请一个UCI上下文.
    if (!ctx) {
		debug(LOG_ERR, "Out of memory");
		return -1;
	}
    if (UCI_OK != uci_load(ctx, YDCQ_INFO_CONFIG_FILE, &pkg)) {
        goto cleanup; //如果打开UCI文件失败,则跳到末尾 清理 UCI 上下文.
    }


    /*遍历UCI的每一个节*/
    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        // 将一个 element 转换为 section类型, 如果节点有名字,则 s->anonymous 为 false.
        // 此时通过 s->e->name 来获取.
        // 此时 您可以通过 uci_lookup_option()来获取 当前节下的一个值.
        if (NULL != (value = uci_lookup_option_string(ctx, s, "version"))) {
            careful_free(__system_info.version);
            __system_info.version = safe_strdup(value); //如果您想持有该变量值，一定要拷贝一份。当 pkg销毁后value的内存会被释放。
        } else {
            debug(LOG_ERR, "fail to get system version");
            error_flag = 1;
        }
        if (NULL != (value = uci_lookup_option_string(ctx, s, "model"))) {
            careful_free(__system_info.model);
            __system_info.model = safe_strdup(value);
        } else {
            debug(LOG_ERR, "fail to get system model");
            error_flag = 1;
        }
        if (NULL != (value = uci_lookup_option_string(ctx, s, "date"))) {
            careful_free(__system_info.creation_date);
            __system_info.creation_date = safe_strdup(value);
        } else {
            debug(LOG_ERR, "fail to get system creation date");
            error_flag = 1;
        }
        // 如果您不确定是 string类型 可以先使用 uci_lookup_option() 函数得到Option 然后再判断.
        // Option 的类型有 UCI_TYPE_STRING 和 UCI_TYPE_LIST 两种.
    }
    uci_unload(ctx, pkg); // 释放 pkg

    if (error_flag) {
        return -1;
    }
    return 0;

cleanup:
    uci_free_context(ctx);
    ctx = NULL;
    return -1;
}
#else
static int get_1dcq_system_info()
{
    __system_info.version = safe_strdup(SF_VERSION);
    __system_info.model = safe_strdup(MODEL);
    __system_info.creation_date = safe_strdup(MAKE_DATE);

    return 0;
}
#endif


#define UNKOWN_SYSTEM_INFO "unkown"
static void generate_unkown_system_info()
{
    if (NULL == __system_info.version) {
        __system_info.version = safe_strdup(UNKOWN_SYSTEM_INFO);
    }
    if (NULL == __system_info.model) {
        __system_info.model = safe_strdup(UNKOWN_SYSTEM_INFO);
    }
    if (NULL == __system_info.creation_date) {
        __system_info.creation_date = safe_strdup(UNKOWN_SYSTEM_INFO);
    }
    if (NULL == __system_info.snid) {
        __system_info.snid = safe_strdup(UNKOWN_SYSTEM_INFO);
    }
}

#define MAX_RETRY_TIME (4UL)
int get_system_info(system_info_t *buf)
{
    int ret;
    int retry = 0;
    s_config *config = config_get_config();

    pthread_mutex_lock(&get_system_info_mutex);
    if (__system_info.info_ok) {
        memcpy((char *)buf, (char *)&__system_info, sizeof(system_info_t));
         pthread_mutex_unlock(&get_system_info_mutex);
        return 0;
    }

    do {
        ret = get_1dcq_system_info();
    } while(ret && retry++ < MAX_RETRY_TIME && (sleep(1), 1));
    if (retry >= MAX_RETRY_TIME) {
        generate_unkown_system_info();
        pthread_mutex_unlock(&get_system_info_mutex);
        return -1;
    }

    retry = 0;
	do {
        //careful_free(__system_info.snid);
        __system_info.snid = config_get_config()->gw_id; //get_iface_mac(config->gw_interface);
    } while (NULL == __system_info.snid && retry++ < MAX_RETRY_TIME && (sleep(1), 1));
    if (retry >= MAX_RETRY_TIME) {
        generate_unkown_system_info();
        pthread_mutex_unlock(&get_system_info_mutex);
        return -1;
    }

    __system_info.info_ok = 1;
    memcpy((char *)buf, (char *)&__system_info, sizeof(system_info_t));

    pthread_mutex_unlock(&get_system_info_mutex);
    return 0;
}

#ifdef __OPENWRT__
int uci_set_config(const char *config, const char *section, const char *option, const char *value)
{
    if (!config || !section || !option || !value) {
        debug(LOG_ERR, "invalid parameters");
        return -1;
    }

    struct uci_context *ctx;
    struct uci_ptr ptr ={
        .package = config,
        .section = section,
        .option = option,
        .value = value,
    };

    ctx = uci_alloc_context();
    if (!ctx) {
        debug(LOG_ERR, "fail to do uci_alloc_context");
        return -1;
    }

    debug(LOG_DEBUG, "uci set: %s %s %s %s", ptr.package, ptr.section, ptr.option, ptr.value);
    uci_set(ctx, &ptr);

    uci_commit(ctx, &ptr.p, false);
    uci_unload(ctx, ptr.p);

    uci_free_context(ctx);
    return 0;
}

/* xxxc something not free, can not sequential-call */
int uci_get_config(const char *config, const char *section, const char *option, char *buf)
{
    struct uci_context *c;
    struct uci_ptr p;
    char a[MAX_BUF];

    if (!config || !section || !option || !buf) {
        debug(LOG_ERR, "invalid parameters");
        return -1;
    }

    if (!(strcat(a, config) && strcat(a, ".") && strcat(a, section) && strcat(a, ".") && strcat(a, option))) {
        debug(LOG_ERR, "fail to strcat parameters");
        return -1;
    }

    c = uci_alloc_context ();
    if (!c) {
        perror("uci");
        return -1;
    }

    if (uci_lookup_ptr (c, &p, a, true) != UCI_OK)
    {
        perror("uci");
        goto Error;
    }

    if(!p.o || !p.o->v.string)
    {
        goto Error;
    }

    memcpy(buf, p.o->v.string, strlen(p.o->v.string) + 1);
    uci_unload(c, p.p);
    uci_free_context (c);
    return 0;

 Error:
    uci_unload(c, p.p);
    uci_free_context (c);
    return -1;
}

#else

int uci_get_config(const char *config, const char *section, const char *option, char *buf)
{
    return 0;
}

int uci_set_config(const char *config, const char *section, const char *option, const char *value)
{
    return 0;
}

int uci_get_cnf(const char *config, const char *section, const char *option, char *buf)
{
    return 0;
}

#endif


/**
 * format the mac address
 * eg: format_mac(macaddress, "00:00:00:00:00:01", ":")
 * return: success 0, fail errno
 */
int format_mac(_OUT char *arr, _IN const char *mac, const char *del)
{
    char *s =NULL;
    int i= 0;
    char temp[1];
    char str[MAC_ADDR_LEN] = {0};

#ifdef __MTK_SDK__
    ASSERT_RET(arr, -1);
    ASSERT_RET(str, -1);
    ASSERT_RET(del, -1);
    ASSERT_RET(is_mac_valid(str), -1);
#endif

    memcpy(str, mac, strlen(mac));
    printf("str %s, del %s", str, del);

    s=strtok(str,del);
    while(s != NULL)
    {
        printf("%s", s);
        if (!isxdigit(s[0]))
        {
            printf("mac illegal");
            return -1;
        }
        if (!isxdigit(s[1]))
        {
#if 1
            temp[0] = s[0];
            printf("temp %c", temp[0]);
            s[0] = '0';
            s[1] = temp[0];
#else
            printf("mac illegal");
            return -1;
#endif
        }

        arr[i++] = s[0];
        arr[i++] = s[1];
        s = strtok(NULL,del);
    }

    return 0;
}

int id_to_mac(char *buf, char *device_id)
{
    if (!buf || !device_id) {
        return -1;
    }

    sprintf(buf, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
        device_id[0], device_id[1], device_id[2], device_id[3], device_id[4], device_id[5],
        device_id[6], device_id[7], device_id[8], device_id[9], device_id[10], device_id[11]);

    return 0;
}

int get_hostname(const char *check_mac, char *name_buf)
{
	FILE *fp;
    char get_mac[MAC_ADDR_LEN] = {0};
	struct dhcpOfferedAddr {
		unsigned char hostname[16];
		unsigned char mac[16];
		unsigned long ip;
		unsigned long expires;
	} lease;

    memset(&lease, 0, sizeof(lease));

	execute_cmd("killall -q -USR1 udhcpd", NULL);

	fp = fopen("/var/udhcpd.leases", "r");
    if (NULL == fp) {
    	return -1;
    }
	while (!feof(fp) && fread(&lease, 1, sizeof(lease), fp) == sizeof(lease)) {
        sprintf(get_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            lease.mac[0], lease.mac[1], lease.mac[2], lease.mac[3], lease.mac[4], lease.mac[5]);
		if (strncasecmp(get_mac, check_mac, MAC_ADDR_LEN) == 0) {
            memcpy(name_buf, lease.hostname, 16);
            fclose(fp);
            return 0;
        }
	}
	fclose(fp);
	return -1;
}

struct MemoryStruct {
        char *data;
        size_t size;
};

/*******http new add**********/
static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
	char *ptr_data;
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)data;

	ptr_data = (char *)realloc(mem->data, mem->size + realsize + 1);
	if( ptr_data == NULL ) {
		if( mem->data ) {
			free(mem->data);
			mem->data = NULL;
		}
		return -1;
	}

	mem->data = ptr_data;
	memcpy(&(mem->data[mem->size]), ptr, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0;

	return realsize;
}

/**
 * cURL http get function.
 * the returned string (if not NULL) needs to be freed by the caller
 *
 * @param u url to retrieve
 * @param q optional query parameters
 * @param customheader specify custom HTTP header (or NULL for none)
 * @return returned HTTP
 */
char *curl_http_get (const char *url, unsigned long timeout)
{
	CURL *curl;
	CURLcode result;

	struct MemoryStruct chunk;

	chunk.data = NULL;
	chunk.size = 0;

	curl = curl_easy_init();
	if(!curl) {
	    return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout * 2);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);

	result = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	if (result == CURLE_OK) {
		return chunk.data;
    }

	debug(LOG_ERR, "GET: code='%d', error='%s'", result, curl_easy_strerror(result));
	if( chunk.data )free(chunk.data);

	return NULL;
}
/*************************************************
Function: curl_http_get2
Description: download a file from server
Called By:
Table Accessed:
Table Updated:
Input:
			const char *url: address of server
			const char * outout: file name of downloaded
			unsigned long timeout: timeout
Return:
Others:
*************************************************/
int curl_http_get2( const char *url, unsigned long timeout, const char * outout )
{
	CURL *handle = NULL;
	CURLcode result = -1;
	FILE * fp_outout = NULL;

	fp_outout = fopen(outout, "w+");
	if( fp_outout == NULL ) return -1;

	handle = curl_easy_init();
	if( handle == NULL ){
		fclose(fp_outout);
		fp_outout = NULL;
		return -1;
	}

	curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(handle, CURLOPT_TIMEOUT, timeout * 2);
	curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, timeout);
	curl_easy_setopt(handle, CURLOPT_URL, url);
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, fp_outout);
	result = curl_easy_perform(handle);
	curl_easy_cleanup(handle);
	handle = NULL;

	fflush( fp_outout );
	fclose( fp_outout );
	fp_outout = NULL;

	if(result == CURLE_OK)
		return 0;

	debug(LOG_ERR, "GET2: code='%d', error='%s'", result, curl_easy_strerror(result));
	return -1;
}

/*************************************************
Function: curl_http_post
Description: post data to server
Called By:
Table Accessed:
Table Updated:
Input:
			const char *url: address of server
			const char *customheader: stureture of data
			const char *data: data to post
			unsigned long timeout: timeout
Return:
Others:
*************************************************/
char *curl_http_post (const char *url, const char *customheader, const char *data, unsigned long timeout)
{
	CURL *curl;
	CURLcode result;
	struct curl_slist *slist = NULL;

	struct MemoryStruct chunk;

	chunk.data = NULL;
	chunk.size = 0;

	curl = curl_easy_init();
	if(!curl) return NULL;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	if ( customheader ) {
		slist = curl_slist_append(slist, customheader);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
	}

	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout * 2);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);

	result = curl_easy_perform(curl);
	if( slist )curl_slist_free_all(slist);
	curl_easy_cleanup(curl);

	if (result == CURLE_OK)
		return chunk.data;

	debug(LOG_ERR, "POST: code='%d', error='%s'", result, curl_easy_strerror(result));
	if( chunk.data )free(chunk.data);

	return NULL;
}


