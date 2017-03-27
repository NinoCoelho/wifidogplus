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
#include "fw_iptables.h"
#include "http.h"
#include "whitelist_thread.h"
#include "list.h"
#include "watchdog.h"
#include "client_list.h"

#ifdef __OPENWRT__
#include <uci_config.h>
#include <uci.h>
#endif

#if (GET_WHITE_FROM_UBUS)
#include <libubox/blobmsg_json.h>
#include "wifiga_ubus_client.h"
static void parse_white_url(struct ubus_request *req, int type, struct blob_attr *msg);
#endif

#ifdef THIS_THREAD_NAME
#undef THIS_THREAD_NAME
#endif
#define THIS_THREAD_NAME    THREAD_WHITE_LIST_NAME

#define MAX_URL_LEN (128UL)
#define MAX_MEM (10 *1024UL)


typedef struct passwd_s {
    //char                passwd[20];
    time_t  time;
} passwd_t;

typedef struct mac_node_s {
    struct dlist_head    list;
    char                mac[MAC_ADDR_LEN];
} mac_node_t;

typedef struct url_node_s {
    struct dlist_head    list;
    char                url[MAX_URL_LEN];
} url_node_t;

static struct dlist_head history_mac_list ;
static struct dlist_head server_mac_list;
static char *white_list_mac_server = NULL;
static char *white_list_mac_history = NULL;//add jore

static struct dlist_head history_url_list;
static struct dlist_head server_url_list;
static char *white_list_url_server = NULL;
static char *white_list_url_history = NULL;//add jore

static passwd_t g_passwd;


static int update_passwd(void);
static int whitelistCommand( char *request, WHITELISTPROCESS funcProcess);
// set whitelist && pwd
static int proc_Whitelist(char *reponse);
static int cmm_Whitelist();
static int setWhiteurl(char *reponse);
static int setWhitemac(char *reponse);
static int setSSID24(char *reponse);
static int setSSID5(char *reponse);
static int setPasswd(char *reponse);
static int getSSID24(char *buf);
static void uciSetSSID24(char *value);
static int getSSID5(char *buf);
static void uciSetSSID5(char *value);


void thread_white_list(char *arg)
{
    pthread_cond_t          cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t         cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct  timespec        timeout;

    INIT_DLIST_HEAD(&history_mac_list);
    INIT_DLIST_HEAD(&server_mac_list);
    INIT_DLIST_HEAD(&history_url_list);
    INIT_DLIST_HEAD(&server_url_list);

    memset(&g_passwd, 0, sizeof(g_passwd));
    g_passwd.time = time(NULL);

    while (1) {
        pthread_watchdog_feed(THIS_THREAD_NAME);
#if (GET_WHITE_FROM_UBUS)
        ubus_call("wifiga", "rcfg", NULL, parse_white_url, NULL);
#else
        if ( cmm_Whitelist() != 0)
        {
            printf( "White list set fail \n");
        }
#endif
        pthread_watchdog_feed(THIS_THREAD_NAME);
        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }

    mac_node_t *mac_pos, *mac_pos_tmp;
    dlist_for_each_entry_safe(mac_pos, mac_pos_tmp, &server_mac_list, mac_node_t, list) {
        dlist_del(&mac_pos->list);
        careful_free(mac_pos);
    }
    dlist_for_each_entry_safe(mac_pos, mac_pos_tmp, &history_mac_list, mac_node_t, list) {
        dlist_del(&mac_pos->list);
        careful_free(mac_pos);
    }
    url_node_t *url_pos, *url_pos_tmp;
    dlist_for_each_entry_safe(url_pos, url_pos_tmp, &server_url_list, url_node_t, list) {
        dlist_del(&url_pos->list);
        careful_free(url_pos);
    }
    dlist_for_each_entry_safe(url_pos, url_pos_tmp, &history_url_list, url_node_t, list) {
        dlist_del(&url_pos->list);
        careful_free(url_pos);
    }

    careful_free(white_list_mac_server);
    careful_free(white_list_mac_history);
    careful_free(white_list_url_server);
    careful_free(white_list_url_history);
}

/****************************************
* 函数:whitelistCommand
* 输入: request 输入请求funcProcess:返回处理函数
* 返回: 0 正确
* 作用:
**/
static int whitelistCommand( char *request, WHITELISTPROCESS funcProcess)
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
    return funcProcess(request);
}

static int  proc_Whitelist(char *reponse)
{
    if (strstr(reponse, "Pong") == 0)
    {
        debug(LOG_DEBUG, "Not pong, you should set White list!");
        if (config_get_config()->autoSsid) {
            setSSID24(reponse);
            pthread_watchdog_feed(THIS_THREAD_NAME);
    		setSSID5(reponse);
            pthread_watchdog_feed(THIS_THREAD_NAME);
        }
        if (config_get_config()->autoPassword) {
		    setPasswd(reponse);
        }
        pthread_watchdog_feed(THIS_THREAD_NAME);
#if WIFIDOG_ON_OFF
        setWhiteurl(reponse);
        pthread_watchdog_feed(THIS_THREAD_NAME);
		setWhitemac(reponse);
#endif
        /* FIXME */
    }
    else
    {
        debug(LOG_DEBUG, "Pong, White list need not set");
    }
    return OK;
}


static int cmm_Whitelist()
{
    static char request[MAX_BUF]={0};
    t_auth_serv *auth_server = get_auth_server();
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
            auth_server->authserv_path,
            auth_server->authserv_config_script_path_fragment,//add jore
            info.model,
            info.version,
            info.snid,
            VERSION,
            auth_server->authserv_hostname);
            debug(LOG_DEBUG, "request [%s]", request);

    return whitelistCommand(request,proc_Whitelist);
}

static int Whiteurl_add_to_iptables(char *url)
{
    if (!url) {
        return -1;
    }

    iptables_do_command("-t filter -A " TABLE_WIFIDOG_WHITE_URL " -d %s -j ACCEPT", url);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_WHITE_URL " -d %s -j ACCEPT", url);

    return 0;
}

static int Whiteurl_del_from_iptables(char *url)
{
    if (!url) {
        return -1;
    }

    iptables_do_command("-t filter -D " TABLE_WIFIDOG_WHITE_URL " -d %s -j ACCEPT", url);
    iptables_do_command("-t nat -D " TABLE_WIFIDOG_WHITE_URL " -d %s -j ACCEPT", url);

    return 0;
}

static int print_url_list()
{
    url_node_t *pos;

    debug(LOG_DEBUG, "print server_url_list");
    dlist_for_each_entry(pos, &server_url_list, url_node_t, list) {
        printf("%s, ", pos->url);
    }
    printf("\n");
    debug(LOG_DEBUG, "print history_url_list");
    dlist_for_each_entry(pos, &history_url_list, url_node_t, list) {
        printf("%s, ", pos->url);
    }
    printf("\n");

    return 0;
}

static int setWhiteurlDiff()
{
    url_node_t *server_pos, *server_pos_tmp;
    url_node_t *history_pos, *history_pos_tmp;
    int exist_flag;
    url_node_t *new_node;
    int count = 0;

    //print_url_list();
    dlist_for_each_entry_safe(server_pos, server_pos_tmp, &server_url_list, url_node_t, list) {
        exist_flag = 0;
        dlist_for_each_entry_safe(history_pos, history_pos_tmp, &history_url_list, url_node_t, list) {
            if (!strncasecmp(server_pos->url, history_pos->url, MAX_URL_LEN)) {
                dlist_del(&history_pos->list);
                careful_free(history_pos);
                exist_flag = 1;
                break;
            }
        }

        if (!exist_flag) {
            Whiteurl_add_to_iptables(server_pos->url);
            OVERFLOW_FEED(THIS_THREAD_NAME, count, MAX_DO_COMMAND_CONTINUE);
        }
    }
    //print_url_list();

    dlist_for_each_entry_safe(history_pos, history_pos_tmp, &history_url_list, url_node_t, list) {
        Whiteurl_del_from_iptables(history_pos->url);
        dlist_del(&history_pos->list);
        careful_free(history_pos);
        OVERFLOW_FEED(THIS_THREAD_NAME, count, MAX_DO_COMMAND_CONTINUE);
    }
    //print_url_list();

    dlist_for_each_entry_safe(server_pos, server_pos_tmp, &server_url_list, url_node_t, list) {
        dlist_move(&server_pos->list, &history_url_list);
    }
    //print_url_list();

    return 0;
}

static int setWhiteurl(char *reponse)
{
    //reponse = "white_list=www.baidu.com,www.sina.com,www.pudn.com,www.126.com\r\n"; // just for test
    if(strstr(reponse, "white_list=") !=0) {
	    char *start = strstr(reponse,"white_list=") + strlen("white_list=");
		char *stop = strstr(start, "\r\n") + 1; /* adding 1 for '\0' */
		int len = stop - start;

		if (len > MAX_MEM) {
			debug(LOG_ERR, "Error :the white_list value strlen Beyond, strlen:[%d],maxlen:[%d]", len,MAX_MEM);
			len = MAX_MEM;
		}
		white_list_url_server = (char *)safe_malloc(len);
	    memset(white_list_url_server,0,len);

        getKeyvalue(white_list_url_server, reponse,"white_list=");
        debug(LOG_DEBUG, "whitelist url [%s]", white_list_url_server);
    }

    if(!white_list_url_server
        || !strncasecmp(white_list_url_server, "null", strlen("null") + 1)
        || (strlen(white_list_url_server) == 0)
        || (white_list_url_history && !strncasecmp(white_list_url_history, white_list_url_server, strlen(white_list_url_server) + 1))) {
        debug(LOG_DEBUG, "did not need to process url white list");
        goto SUCCESS;
    }

    careful_free(white_list_url_history);
    white_list_url_history = safe_strdup(white_list_url_server);

    /* add to list */
    char *seps = ",";
	char *url_single = strtok(white_list_url_server, seps);
	while(url_single)
	{
	    debug(LOG_DEBUG, "set white_list_url_server single:[%s]", url_single);
        url_node_t *new_node = (url_node_t *)safe_malloc(sizeof(url_node_t));
        memcpy(new_node->url, url_single, MAX_URL_LEN);
        dlist_add(&new_node->list, &server_url_list);
	    url_single = strtok(NULL, seps);
	}

    setWhiteurlDiff();

SUCCESS:
    careful_free(white_list_url_server);
    return 0;
}

static int print_mac_list()
{
    mac_node_t *pos;
    debug(LOG_DEBUG, "print server_mac_list");
    dlist_for_each_entry(pos, &server_mac_list, mac_node_t, list) {
        printf("%s, ", pos->mac);
    }
    printf("\n");
    debug(LOG_DEBUG, "print history_mac_list");
    dlist_for_each_entry(pos, &history_mac_list, mac_node_t, list) {
        printf("%s, ", pos->mac);
    }
    printf("\n");

    return 0;
}

static int setWhiteMacDiff()
{
    mac_node_t *server_pos, *server_pos_tmp;
    mac_node_t *history_pos, *history_pos_tmp;
    int exist_flag;
    mac_node_t *new_node;
    int count = 0;

    //print_mac_list();
    dlist_for_each_entry_safe(server_pos, server_pos_tmp, &server_mac_list, mac_node_t, list) {
        exist_flag = 0;
        dlist_for_each_entry_safe(history_pos, history_pos_tmp, &history_mac_list, mac_node_t, list) {
            if (!strncasecmp(server_pos->mac, history_pos->mac, MAC_ADDR_LEN)) {
                dlist_del(&history_pos->list);
                careful_free(history_pos);
                exist_flag = 1;
                break;
            }
        }

        if (!exist_flag) {
            (void)client_list_add(server_pos->mac);
            (void)client_list_set_auth(server_pos->mac, CLIENT_CONFIG);
            (void)iptables_fw_allow_mac(server_pos->mac);
            (void)iptables_fw_untracked_mac(server_pos->mac);
            OVERFLOW_FEED(THIS_THREAD_NAME, count, MAX_DO_COMMAND_CONTINUE);
        }
    }
    //print_mac_list();

    dlist_for_each_entry_safe(history_pos, history_pos_tmp, &history_mac_list, mac_node_t, list) {
        (void)client_list_set_auth(history_pos->mac, CLIENT_CHAOS);
        (void)iptables_fw_tracked_mac(history_pos->mac);    /* it is necessary */
        (void)iptables_fw_deny_mac(history_pos->mac);
        dlist_del(&history_pos->list);
        careful_free(history_pos);
        OVERFLOW_FEED(THIS_THREAD_NAME, count, MAX_DO_COMMAND_CONTINUE);
    }
    //print_mac_list();

    dlist_for_each_entry_safe(server_pos, server_pos_tmp, &server_mac_list, mac_node_t, list) {
        dlist_move(&server_pos->list, &history_mac_list);
    }
    //print_mac_list();

    return 0;
}

static int setWhitemac(char *reponse)
{
    //reponse = "white_mac=00:11:22:33:44:55,00:11:22:33:44:56,AC:A2:13:3B:85:83,38:bc:1a:0d:7e:b2\r\n"; // just for test
    if(strstr(reponse, "white_mac=") !=0) {
	    char *start = strstr(reponse,"white_mac=") + strlen("white_mac=");
		char *stop = strstr(start, "\r\n") + 1; /* adding 1 for '\0' */
		int len = stop - start;

		if (len > MAX_MEM) {
			debug(LOG_ERR, "Error :the white_mac value strlen Beyond, strlen:[%d],maxlen:[%d]", len,MAX_MEM);
			len = MAX_MEM;
		}
		white_list_mac_server = (char *)safe_malloc(len);
	    memset(white_list_mac_server,0,len);

        getKeyvalue(white_list_mac_server, reponse,"white_mac="); // xxxc here got a bug, because of MAX_MEM limit
        debug(LOG_DEBUG, "whitelist mac: [%s]", white_list_mac_server);
    }

    if(!white_list_mac_server
        || !strncasecmp(white_list_mac_server, "null", strlen("null") + 1)
        || (strlen(white_list_mac_server) == 0)
        || (white_list_mac_history && !strncasecmp(white_list_mac_history, white_list_mac_server, strlen(white_list_mac_server) + 1))) {
        debug(LOG_DEBUG, "did not need to process mac white list");
        goto SUCCESS;
    }

    careful_free(white_list_mac_history);
    white_list_mac_history = safe_strdup(white_list_mac_server);

    /* add to list */
    char *seps = ",";
	char *mac_single = strtok(white_list_mac_server, seps);
	while(mac_single && is_mac_valid(mac_single))
	{
	    debug(LOG_DEBUG, "set white_list_mac_server single:[%s]", mac_single);
        mac_node_t *new_node = (mac_node_t *)safe_malloc(sizeof(mac_node_t));
        memcpy(new_node->mac, mac_single, MAC_ADDR_LEN);
        dlist_add(&new_node->list, &server_mac_list);
	    mac_single = strtok(NULL, seps);
	}

    setWhiteMacDiff();

SUCCESS:
    careful_free(white_list_mac_server);
    return 0;
}

static int setSSID24(char *reponse)
{
    char ssid24[33] = {0};
    char ssid24_server[33] = {0};

    if(strstr(reponse,"ssid24=") !=0)
    {
        getKeyvalue(ssid24_server, reponse,"ssid24=");
        debug(LOG_DEBUG, "ssid24: [%s]", ssid24_server);
    }

    if(strncasecmp(ssid24_server, "null", strlen("null") + 1) && strlen(ssid24_server) != 0) {
    	if (getSSID24(ssid24)) {
			debug(LOG_DEBUG, "can not get ssid24 using uci");
			return -1;
		}
	    debug(LOG_DEBUG, "current ssid24 = [%s]", ssid24);

	    char ydcq_ssid24[33] = "一点传奇-";
	    strcat(ydcq_ssid24,ssid24_server);
        if(strcmp(ssid24,ydcq_ssid24) != 0) {
	        do_execute("iwpriv ra0 set SSID=%s",ydcq_ssid24);
#ifdef __MTK_SDK__
            bl_set_config("WlanSSID", ydcq_ssid24);
#endif
         }
    }
	return 0;
}

static int setSSID5(char *reponse)
{
	char ssid5[33] = {0};
	char ssid5_server[33] = {0};
	if(strstr(reponse,"ssid5=") !=0)
	    {
	        getKeyvalue(ssid5_server, reponse,"ssid5=");
	        debug(LOG_DEBUG, "ssid5: [%s]", ssid5_server);
	    }

    if(strncasecmp(ssid5_server, "null", strlen("null") + 1) && strlen(ssid5_server) != 0) {
    	if (getSSID5(ssid5)) {
			debug(LOG_DEBUG, "can not get the ssid5 ...");
			return -1;
		}
	    debug(LOG_DEBUG, "current ssid5 = [%s]", ssid5);

	    char ydcq_ssid5[33] = "一点传奇-";
        strcat(ydcq_ssid5,ssid5_server);
        if(strcmp(ssid5,ydcq_ssid5) != 0){
          do_execute("iwpriv rai0 set SSID=%s",ydcq_ssid5);
          // xx uciSetSSID5(ydcq_ssid5);
        }
    }
	return 0;
}

#define DEFAULT_PASSWORD        "1dcq"
static int setPasswd(char *reponse)
{
	char *pwd;
	char pwd_server[32] = {0};
    char pwd_history[32] = DEFAULT_PASSWORD;
    FILE *file;
    int ret;

#ifdef __MTK_SDK__
    if (bl_get_config("Password", pwd_history)) {
        memcpy(pwd_history, DEFAULT_PASSWORD, strlen(DEFAULT_PASSWORD));
    }
#else
    memcpy(pwd_history, DEFAULT_PASSWORD, strlen(DEFAULT_PASSWORD));
#endif

	if(strstr(reponse,"pwd=") !=0) {
        getKeyvalue(pwd_server, reponse,"pwd=");
    }

    if(strncasecmp(pwd_server, "null", strlen("null") + 1) && strlen(pwd_server) != 0) {
        if(strcmp(pwd_history, pwd_server) != 0) {
#ifdef __MTK_SDK__
            do_execute("chpasswd.sh 1dcq %s", pwd_server);
            if (bl_set_config("Password", pwd_server)) {
                debug(LOG_ERR, "fail to set password");
                return -1;
            }
#else
            debug(LOG_ERR, "fail to set password");
#endif
        }
    }
    return 0;
}

#ifdef __OPENWRT__ //xxxc
static int getSSID24(char *buf)
{
    struct uci_context *c;
    struct uci_ptr p;
    char *a = strdup ("wireless.@wifi-iface[0].ssid");
    if (!a) {
        return -1;
    }

    c = uci_alloc_context ();
    if (!c) {
        perror("uci");
        free(a);
        return -1;
    }

    if (uci_lookup_ptr (c, &p, a, true) != UCI_OK)
    {
      perror("uci");
      goto Error;
    }

    if(!p.o || !p.o->v.string)
    {
    debug(LOG_DEBUG, "%s: wifi ssid24 ra0 not exist...", __func__);
    goto Error;
    }

    memcpy(buf, p.o->v.string, strlen(p.o->v.string) + 1);
    uci_free_context (c);
    free (a);
    return 0;

 Error:
    free(a);
    uci_free_context (c);
    return -1;
}


static void uciSetSSID24(char *value)
{
    debug(LOG_DEBUG, "======uci set wireless ssid24 ========:[%s]", value);
    do_execute("uci set wireless.@wifi-iface[0].ssid=%s && uci commit",value);
}

static int getSSID5(char *buf)
{
    struct uci_context *c;
    struct uci_ptr p;
    char *a = strdup ("wireless.@wifi-iface[1].ssid");
    if (!a) {
        return -1;
    }

    c = uci_alloc_context ();
    if (!c) {
        perror("uci");
        free(a);
        return -1;
    }

    if (uci_lookup_ptr (c, &p, a, true) != UCI_OK)
    {
        perror("uci");
        goto Error;
    }

    if(!p.o || !p.o->v.string)
    {
        debug(LOG_DEBUG, "%s: wifi ssid5G rai0 not exist...", __func__);
        goto Error;
    }

    memcpy(buf, p.o->v.string, strlen(p.o->v.string) + 1);

    uci_free_context (c);
    free (a);
    return 0;

Error:
    free(a);
    uci_free_context (c);
    return -1;

}


static void uciSetSSID5(char *value)
{
    debug(LOG_DEBUG, "======uci set wireless ssid5 ========:[%s]", value);
    do_execute("uci set wireless.@wifi-iface[1].ssid=%s && uci commit",value);
}
#else
static int getSSID24(char *buf)
{
#ifdef __MTK_SDK__
    if (bl_get_config("WlanSSID", buf)) {
        return -1;
    }
#endif

    return 0;
}

static void uciSetSSID24(char *value)
{
}

static int getSSID5(char *buf)
{
    return -1;
}

static void uciSetSSID5(char *value)
{
}

#endif

#if (GET_WHITE_FROM_UBUS)
#define WHITE_URL_PREFIX "white_list="
static void parse_white_url(struct ubus_request *req, int type, struct blob_attr *msg)
{
    int ret = 0;
    char *data;
    char *white_url = NULL;
    int i;
    struct json_object *get_object = NULL;
    struct json_object *white_url_object = NULL;
    char *reponse = NULL;

    data = blobmsg_format_json(msg, true);
    if(!data) {
        debug(LOG_ERR, "No data");
        ret = -1;
        goto RET_0;
    }
	debug(LOG_DEBUG, "msg [%s]", data);

    get_object = json_tokener_parse(data);
    if(!get_object) {
        debug(LOG_ERR, "No get_object");
        ret = -1;
        goto RET_1;
    }

    white_url_object = json_object_object_get(get_object, "white_url");
    if(!white_url_object) {
        debug(LOG_ERR, "No white_url_object");
        ret = -1;
        goto RET_2;
    }
    white_url = (char *)json_object_get_string(white_url_object);
    if(!white_url) {
        debug(LOG_ERR, "No white_url");
        ret = -1;
        goto RET_2;
    }

    reponse = safe_malloc(strlen(white_url) + strlen(WHITE_URL_PREFIX) + 1);
    memcpy(reponse, WHITE_URL_PREFIX, strlen(WHITE_URL_PREFIX));
    memcpy(reponse + strlen(WHITE_URL_PREFIX), white_url, strlen(white_url));
    setWhiteurl(reponse);

RET_2:
    json_object_put(get_object);
RET_1:
    careful_free(data);
RET_0:
    return;
}
#endif

void TestWhitelist_func()
{
#if 0 /*Test uciSetSSID5() getSSID5()  uciSetSSID24() getSSID24()*/
    int i;
    char ssid5[64]={0};
    char ssid5_new[20]={0};

    char ssid24[64]={0};
    char ssid24_new[20]={0};

    for(i=0;i < 100;i++){
        memset(ssid5, 0, 64);
        memset(ssid5_new, 0, 20);
        sprintf(ssid5_new,"1dcq5g-%d",i);
        getSSID5(ssid5);
        debug(LOG_DEBUG, "current ssid5 = [%s]", ssid5);

        uciSetSSID5(ssid5_new);
        debug(LOG_DEBUG, "%s: ==Test jore %d, set ssid5:[%s]=====", __func__,i,ssid5_new);

        memset(ssid24, 0, 64);
        memset(ssid24_new, 0, 20);
        sprintf(ssid24_new,"1dcq24-%d",i);
        getSSID24(ssid24);
        debug(LOG_DEBUG, "current ssid24 = [%s]", ssid24);

        uciSetSSID24(ssid24_new);
        debug(LOG_DEBUG, "%s: ==Test jore %d, set ssid24:[%s]=====", __func__,i,ssid24_new);
    }
#endif
#if 0 /* Test setPasswd()*/
    char server_pwd[20]={0};
    int i;
    for(i=0;i<1000;i++){
         memset(server_pwd, 0, 20);
         sprintf(server_pwd,"pwd=1dcq%d",i);
         setPasswd(server_pwd);
        }
#endif
}

