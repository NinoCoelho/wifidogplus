#!/bin/sh
#
# script file for traffic control (QoS)
# only use for wifidog
#

wd_qos_en=`uci get wifidog.@wifidog[0].qos_enable`
lanip=`uci -q get network.lan.ipaddr`
lanip_pre=`echo "$lanip" | sed 's/[0-9]\{1,3\}$//g'`
ip_start=`uci -q get dhcp.lan.start`
ip_end=$((`uci -q get dhcp.lan.limit`+$ip_start))
uplink_speed=`uci get wifidog.@wifidog[0].uplink_common`
downlink_speed=`uci get wifidog.@wifidog[0].downlink_common`

if [ "$wd_qos_en" != "1" ]; then
    exit 0
fi

start(){
    i=$ip_start;
    while [ $i -le $ip_end ]
    do
        qos-set.sh 2,${lanip_pre}${i},${lanip_pre}${i},0,${uplink_speed},${downlink_speed},1,1,${i}
        i=`expr $i + 1`
    done
}

stop(){
    i=$ip_start;
    while [ $i -le $ip_end ]
    do
        qos-set.sh 2,${lanip_pre}${i},${lanip_pre}${i},0,${uplink_speed},${downlink_speed},0,1,${i}
        i=`expr $i + 1`
    done
}

test() {
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -t mangle -Z
    iptables -t mangle -N WiFiDog_br-lan_Qos_OUT
    iptables -t mangle -N WiFiDog_br-lan_Qos_IN
    iptables -t mangle -I PREROUTING 1 -i br-lan -j WiFiDog_br-lan_Qos_OUT
    iptables -t mangle -I POSTROUTING 1 -o br-lan -j WiFiDog_br-lan_Qos_IN

    qos-init.sh
    start
}

case "${1}" in
start)
    (start && echo "Start $0") || echo "error."
    exit 0
    ;;
stop)
    (stop && echo "Stop $0") || echo "error."
    exit 0
    ;;
restart)
    stop
    start
    echo "Restart $0"
    ;;
test)
    test
    echo "Test $0"
    ;;
*)
    echo "$0 start | stop | restart"
    ;;
esac

