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
#ifdef __OPENWRT__
#include <uci.h>
#endif

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
//#include "fw_upd_thread.h"
#include "util.h"
#include "centralserver.h"

#include "http.h"
#include "exchange_thread.h"


httpd *exchgServer = NULL;


static int reqCommand( char *request, REQPROCESS funcProcess);

// auto update firmware
static int  proc_updateFirmware(char *reponse);
static int cmm_updateFirmware();
static int downloadFirmware(char *reponse);
static int updateFirmware(char *reponse);


/****************************************
* 函数:reqCommand
* 输入: request 输入请求funcProcess:返回处理函数
* 返回: 0 正确
* 作用:
**/
static int reqCommand( char *request, REQPROCESS funcProcess)
{
	int sockfd,nfds, done;
	ssize_t numbytes;
    size_t	totalbytes;
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
		else if (nfds == 0)
		{
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return ERR_TIMEOUT;
		}
		else if (nfds < 0)
		{
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

static int backup_config(void)
{
    if (execute_cmd("backup_config.sh", NULL)) {
        debug(LOG_ERR, "fail to run backup_config.sh");
    }

#ifdef __MTK_SDK__
    if (bl_set_config("SoftVerMTD", SF_VERSION)) {
        debug(LOG_ERR, "fail to set version");
    }
    if (bl_set_config("NeedGegu", "1")) {
#endif
#ifdef __OPENWRT__
    if (execute_cmd("uci set quicksettings.quicksettings0.need_regularized=1", NULL)) {
#endif
        debug(LOG_ERR, "fail to set need_regularized");
    }

    return 0;
}

static int  proc_updateFirmware(char *reponse)
{
	//printf("\n\n%s",reponse);
	if (strstr(reponse, "Pong") == 0)
	{
		//debug(LOG_WARNING, "Auth server did NOT say pong!");
		debug(LOG_DEBUG, "Not pong, you should upgrade your router firmware!");
        if(downloadFirmware(reponse)){
            debug(LOG_DEBUG, "===== Have not download the firmware! ======");
        } else {
            updateFirmware(reponse);
        }
		/* FIXME */
	}
	else
	{
		debug(LOG_DEBUG, "Pong, the firmware version for the router is the newest");
    }
	return OK;
}

static int cmm_updateFirmware()
{
	char request[MAX_BUF] = {0};
    system_info_t info;

	t_auth_serv	*auth_server = get_auth_server();

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
            auth_server->authserv_update_script_path_fragment,//add jore
			info.model,
			info.version,
			info.snid,
			VERSION,
			auth_server->authserv_hostname);
			debug(LOG_DEBUG, "request [%s]", request);

    return reqCommand(request,proc_updateFirmware);
}

static int downloadFirmware(char *reponse)
{
    char newestversion[32]={0};
    system_info_t info;

    if(strstr(reponse,"lastestVersion=") !=0)
    {
      //strcpy(newestversion,getKeyvalue(reponse,"lastestVersion"));
       getKeyvalue(newestversion, reponse,"lastestVersion=");
       debug(LOG_DEBUG, "======jore lastestversion==========: %s", newestversion);
    }

    memset((void *)&info, 0, sizeof(system_info_t));
    if (get_system_info(&info)) {
        debug(LOG_ERR, "fail to do get_system_info");
    }
	debug(LOG_DEBUG, "%s:currentVersion:[%s],newestversion[%s], cmp: [%d]",
        __func__,info.version,newestversion,strcmp(newestversion, info.version));

    //memcpy(info.version, "1.0.2", strlen("1.0.2") + 1);
    if (strcmp(newestversion, info.version) > 0)
    {
	    char download_path[256]={0};
	    if(strstr(reponse,"downloadUrl=") !=0)
	    {
		    getKeyvalue(download_path,reponse,"downloadUrl=");
		    debug(LOG_DEBUG, "========jore add111 ===============: [%s]", download_path);
	    }

        if(do_execute("wget %s -O /tmp/latestfirmware.bin",download_path)){
            debug(LOG_ERR, "%s :==== fail!!! =====",__func__);
            return -1;
        }else{
            debug(LOG_DEBUG, "%s : ==== success!!! ====",__func__);
             }
    }else{
 	    return -1;
 	     }
    return 0;
}


static  int updateFirmware(char * reponse)
{
    char md5_server[64]={0};
    if(strstr(reponse,"Md5=") !=0)
    {
      getKeyvalue(md5_server,reponse,"Md5=");
      //debug(LOG_DEBUG, "======jore md5_server==========: %s", md5_server);
    }

    char md5_wgeted[64] = {0};
    if(getInterface_cmd(md5_wgeted,"md5sum /tmp/latestfirmware.bin | awk 'NR==1' | awk '{print $1}'")){
            debug(LOG_ERR, "%s :get md5 fail!!!",__func__);
    }else{
            //  debug(LOG_DEBUG, "======jore33 md5_wgeted==========: %s, size %d\n", md5_wgeted, strlen(md5_wgeted));
            //  debug(LOG_DEBUG, "======jore33 md5_server==========: %s, size %d\n", md5_server, strlen(md5_server));
        debug(LOG_DEBUG, "%s:md5_wgeted:[%s],md5_server[%s],md5 cmp[%d]",
            __func__,md5_wgeted,md5_server,strncasecmp(md5_wgeted, md5_server, strlen(md5_server)));
    }

    if (strncasecmp(md5_wgeted, md5_server, strlen(md5_server)) == 0){
        backup_config();
#ifdef __OPENWRT__
        if(do_execute("sysupgrade -v /tmp/latestfirmware.bin")){ //jore
#endif
#ifdef __MTK_SDK__
       if(do_execute("mtd_write -r write /tmp/latestfirmware.bin Kernel")){
#endif
            debug(LOG_ERR, "%s :==== fail!!! ====",__func__);
        }else{
            debug(LOG_DEBUG, "%s :==== success!!!=====",__func__);
        }
    }
    return 0;
}

/***********************************/
void thread_exg_protocol(char *arg)
{
	pthread_cond_t          cond = PTHREAD_COND_INITIALIZER;
        pthread_mutex_t         cond_mutex = PTHREAD_MUTEX_INITIALIZER;
        struct  timespec        timeout;

        int i = 0;

        while (1) {
                /* Make sure we check the servers at the very begining */
                //debug(LOG_DEBUG, "Running fw_upd()");

		//    printf("=======wait command===\n");
            if (i++ >= 10) {
                return;
            }
		    if ( cmm_updateFirmware() != 0)
		    {
			    printf( "update firmware error\n");
		    }


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
}

