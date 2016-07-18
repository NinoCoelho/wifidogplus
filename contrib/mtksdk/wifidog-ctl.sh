#!/bin/sh

EXTRA_COMMANDS="status"
EXTRA_HELP="        status Print the status of the service"

config_load()
{
    rm -f /etc/wifidog.conf
    rm -f /etc/wifidog-msg.html
    
    ln -s /etc_ro/wifidog-msg.html /etc/wifidog-msg.html

    gateway_id=$(cat /sys/devices/virtual/net/eth2/address|tr a-z A-Z|sed -e 's#:##g')
    nvram_set 2860 wd_gateway_id $gateway_id
    #gateway_id=$(nvram_get 2860 wd_gateway_id)
    
    gateway_interface=$(nvram_get 2860 wd_gateway_interface) 
    gateway_eninterface=$(nvram_get 2860 wd_gateway_eninterface)
    gateway_hostname=$(nvram_get 2860 wd_gateway_hostname) 
    gateway_httpport=$(nvram_get 2860 wd_gateway_httpport) 
    gateway_path=$(nvram_get 2860 wd_gateway_path) 
    gateway_connmax=$(nvram_get 2860 wd_gateway_connmax) 
    ssl_enable=$(nvram_get 2860 wd_ssl_enable) 
    check_interval=$(nvram_get 2860 wd_check_interval)
    client_timeout=$(nvram_get 2860 wd_client_timeout)
    sslport=$(nvram_get 2860 wd_sslport)
    deamo_enable=$(nvram_get 2860 wd_deamo_enable)
    gatewayport=$(nvram_get 2860 wd_gatewayport)
    myz_mac=$(nvram_get 2860 wd_myz_mac)
    bmd_url=$(nvram_get 2860 wd_bmd_url)
    appservhost=$(nvram_get 2860 wd_appservhost)
    appservport=$(nvram_get 2860 wd_appservport)
    appservpath=$(nvram_get 2860 wd_appservpath)
    appservhost1=$(nvram_get 2860 wd_appservhost1)
    appservport1=$(nvram_get 2860 wd_appservport1)
    appservpath1=$(nvram_get 2860 wd_appservpath1)
    appservhost2=$(nvram_get 2860 wd_appservhost2)
    appservport2=$(nvram_get 2860 wd_appservport2)
    appservpath2=$(nvram_get 2860 wd_appservpath2)
    thread_watchdog_timeout=$(nvram_get 2860 wd_thread_watchdog_timeout)
    auto_ssid=$(nvram_get 2860 wd_auto_ssid)
    auto_password=$(nvram_get 2860 wd_auto_password)
    auto_wireless_pw=$(nvram_get 2860 wd_auto_wireless_pw)
    qos_enable=$(nvram_get 2860 wd_qos_enable)
    uplink_vip=$(nvram_get 2860 wd_uplink_vip)
    downlink_vip=$(nvram_get 2860 wd_downlink_vip)
    uplink_common=$(nvram_get 2860 wd_uplink_common)
    downlink_common=$(nvram_get 2860 wd_downlink_common)
    wd_auth_mode=$(nvram_get 2860 wd_auth_mode)
    wd_wechat_officialAccount=$(nvram_get 2860 wd_wechat_officialAccount)
	wd_wechat_shopId=$(nvram_get 2860 wd_wechat_shopId)
	wd_wechat_appId=$(nvram_get 2860 wd_wechat_appId)
	wd_wechat_secretKey=$(nvram_get 2860 wd_wechat_secretKey)
	wd_wechat_extend=$(nvram_get 2860 wd_wechat_extend)
	wd_wechat_forceAttention=$(nvram_get 2860 wd_wechat_forceAttention)
	wd_to_url=$(nvram_get 2860 wd_to_url)
	wd_skip_SuccessPage=$(nvram_get 2860 wd_skip_SuccessPage)
	wd_reAssoc_reAuth=$(nvram_get 2860 wd_reAssoc_reAuth)

echo "
GatewayID $gateway_id
GatewayInterface $gateway_interface
ExternalInterface $gateway_eninterface
AuthServer {
	Hostname $gateway_hostname
	SSLAvailable $ssl_enable
	SSLPort $sslport
	HTTPPort $gateway_httpport
	Path $gateway_path
	}
AppServer {
    appservhost $appservhost
    appservport $appservport
    appservpath $appservpath
}
AppServer {
    appservhost $appservhost1
    appservport $appservport1
    appservpath $appservpath1
}
AppServer {
    appservhost $appservhost2
    appservport $appservport2
    appservpath $appservpath2
}
Daemon $deamo_enable
GatewayPort $gatewayport
CheckInterval $check_interval
ClientTimeout $client_timeout
HTTPDMaxConn $gateway_connmax
TrustedMACList $myz_mac
Thread_watchdog_timeout $thread_watchdog_timeout
Auto_ssid $auto_ssid
Auto_password $auto_password
Auto_wireless_pw $auto_wireless_pw
Qos_enable $qos_enable
Uplink_vip $uplink_vip
Downlink_vip $downlink_vip
Uplink_common $uplink_common
Downlink_common $downlink_common
Wd_auth_mode $wd_auth_mode
Wd_wechat_officialAccount $wd_wechat_officialAccount
Wd_wechat_shopId $wd_wechat_shopId
Wd_wechat_appId $wd_wechat_appId
Wd_wechat_secretKey $wd_wechat_secretKey
Wd_wechat_extend $wd_wechat_extend
Wd_wechat_forceAttention $wd_wechat_forceAttention
Wd_to_url $wd_to_url
Wd_skip_SuccessPage $wd_skip_SuccessPage
Wd_reAssoc_reAuth $wd_reAssoc_reAuth

FirewallRuleSet global {
FirewallRule allow to 168.95.1.1
FirewallRule allow to 210.106.0.20
FirewallRule allow to 114.114.114.114
}
FirewallRuleSet validating-users {
    FirewallRule allow to 0.0.0.0/0
}

FirewallRuleSet known-users {
    FirewallRule allow to 0.0.0.0/0
}

FirewallRuleSet unknown-users {
    FirewallRule allow udp port 53
    FirewallRule allow tcp port 53
    FirewallRule allow udp port 67
    FirewallRule allow tcp port 67
}

FirewallRuleSet locked-users {
    FirewallRule block to 0.0.0.0/0
}
" >> /etc/wifidog.conf
}

white_url_init() {
	url_ch=`echo $bmd_url | sed 's/,/ /g'`
	sleep 4
	for x in $url_ch
	do
		iptables -t filter -A  WiFiDog_br0_WhiteUrl -d $x -j ACCEPT
		iptables -t nat -A WiFiDog_br0_WhiteUrl  -d $x -j ACCEPT
	done
}
  
start() {
	config_load
	/usr/bin/wifidog-init start
	white_url_init
}

stop() {
	/usr/bin/wifidog-init stop
}

status() {
	/usr/bin/wifidog-init status
}

restart() {
        /usr/bin/wifidog-init stop
        sleep 4
        config_load
        /usr/bin/wifidog-init start
		white_url_init
}
 
reload() {                        
        /usr/bin/wifidog-init stop
        sleep 4
        config_load
        /usr/bin/wifidog-init start
		white_url_init
}

case "$1" in
start)
    start
    ;;

stop)
    stop
    ;;

restart)
    restart
    ;;

reload)
    reload
    ;;

status)
    status
    ;;

*)
    echo "$0 start | stop | status | restart | reload"
    ;;
esac

