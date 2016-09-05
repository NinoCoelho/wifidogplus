#
# $Id$
#

bin_PROGRAMS = \
	wifidog \
	wdctl

AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
	-DSYSCONFDIR='"$(sysconfdir)"'
wifidog_LDADD = $(top_builddir)/libhttpd/libhttpd.la

wifidog_SOURCES = commandline.c \
	conf.c \
	debug.c \
	fw_iptables.c \
	firewall.c \
	gateway.c \
	centralserver.c \
	http.c \
	auth.c \
	client_list.c \
	util.c \
	wdctl_thread.c \
	ping_thread.c \
	safe.c \
	httpd_thread.c \
    exchange_thread.c \
	whitelist_thread.c \
	getaddress_thread.c \
	client_access.c \
	get_client.c \
	client_access_preproccess.c \
	test_thread.c \
	client_access_queue.c \
	client_record_queue.c \
	click_record_queue.c \
	siso_queue.c \
	watchdog.c \
	fw_backup.c \
	client_record_backup.c \
	click_record_backup.c \
	qos.c \
	appctl.c \
	wifiga_ubus_client.c

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	fw_iptables.h \
	firewall.h \
	gateway.h \
	centralserver.h \
	http.h \
	auth.h \
	client_list.h \
	util.h \
	wdctl_thread.h \
	wdctl.h \
	ping_thread.h \
	safe.h \
	httpd_thread.h \
    exchange_thread.h \
	whitelist_thread.h \
	getaddress_thread.h \
	list.h \
	hlist.h \
	client_access.h \
	get_client.h \
	client_access_preproccess.h \
	test_thread.h \
	client_access_queue.h \
	client_record_queue.h \
	click_record_queue.h \
	siso_queue.h \
	watchdog.h \
	fw_backup.h \
	client_record_backup.h \
	click_record_backup.h \
	qos.h \
	appctl.h \
	slist.h \
	link_queue.h \
	wifiga_ubus_client.h


wdctl_SOURCES = wdctl.c
