#!/bin/sh
#
# script file for traffic control (QoS)
# only use for wifidog
#

wd_qos_en=`uci get wifidog.@wifidog[0].qos_enable`
lanip=`uci -q get network.lan.ipaddr`
lanip_pre=`echo "$lanip" | sed 's/[0-9]\{1,3\}$//g'`
BRIDGE="br-lan"
wanmode=`uci -q get network.wan.proto`

if [ "$wd_qos_en" != "1" ]; then
    exit 0
fi

# XXX: ignore apclient
if [ "$wanmode" == "pppoe" ]; then
	WAN="ppp0"
elif [ "$wanmode" == "3g" ]; then
	WAN="3g-wan"
else
	WAN="eth0.2"
fi

#echo "$WAN"
#echo "$BRIDGE"

UPLINK_SPEED=1024000
DOWNLINK_SPEED=1024000
#echo "$UPLINK_SPEED"
#echo "$DOWNLINK_SPEED"

wan_pkt_mark=13
lan_pkt_mark=53

#iptables -F -t mangle
#iptables -X -t mangle
#iptables -Z -t mangle

tc qdisc del dev $WAN root 2> /dev/null
tc qdisc del dev $BRIDGE root 2> /dev/null

###### total bandwidth section
### uplink
tc qdisc add dev $WAN root handle 2:0 htb default 2 r2q 64                   
TC_CMD="tc class add dev $WAN parent 2:0 classid 2:1 htb rate ${UPLINK_SPEED}kbit ceil ${UPLINK_SPEED}kbit quantum 30000"
echo "$TC_CMD"
$TC_CMD
TC_CMD="tc class add dev $WAN parent 2:1 classid 2:2 htb rate 1kbit ceil ${UPLINK_SPEED}kbit prio 256 quantum 30000"
echo "$TC_CMD"
$TC_CMD
TC_CMD="tc qdisc add dev $WAN parent 2:2 handle 102: sfq perturb 10"
echo "$TC_CMD"
$TC_CMD

### downlink
tc qdisc add dev $BRIDGE root handle 5:0 htb default 2 r2q 64                   
TC_CMD="tc class add dev $BRIDGE parent 5:0 classid 5:1 htb rate ${DOWNLINK_SPEED}kbit ceil ${DOWNLINK_SPEED}kbit quantum 30000"
echo "$TC_CMD"
$TC_CMD
TC_CMD="tc class add dev $BRIDGE parent 5:1 classid 5:2 htb rate 1kbit ceil ${DOWNLINK_SPEED}kbit prio 256 quantum 30000"
echo "$TC_CMD"
$TC_CMD
TC_CMD="tc qdisc add dev $BRIDGE parent 5:2 handle 502: sfq perturb 10"
echo "$TC_CMD"
$TC_CMD
