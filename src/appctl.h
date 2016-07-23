/**
 * Copyright(C) 2016. JARXI. All rights reserved.
 *
 * appctl.h
 * Original Author : chenjunpei@jarxi.com, 2016-7-12.
 *
 * Description
 */

#ifndef _APPCTL_H_
#define _APPCTL_H_

#define DEFAULT_SOCK	"/tmp/app_control.sock"

#define CTL_UNDEF		0
#define CTL_STATUS      1
#define CTL_STOP		2
#define CTL_CHECK       3
#define CTL_PRINT       4
#define CTL_SYSLOG      5
#define CTL_APPURL      6


typedef struct appctl_s {
	char	*socket;
	int	    command;
	char	*param; /* key */
    char    *config;
    char    *value;
} appctl_t;

int appctl_main(int argc, char **argv);
int appctl_cmd(char *buf, char *pram);
int appctl_appurl(char *buf, char *pram);
int appctl_test(void);

#endif      /* _APPCTL_H_ */

