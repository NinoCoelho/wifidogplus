#!/bin/sh
#
# script file for traffic control (QoS)
# only use for wifidog
#

wd_qos_en=`uci get wifidog.@wifidog[0].qos_enable`
lanip=`uci -q get network.lan.ipaddr`
BRIDGE="br-lan"
wanmode=`uci -q get network.wan.proto`

if [ "$wd_qos_en" != "1" ]; then
    exit 0
fi

if [ $# != 1 ]; then
    echo "usage: $0 [qos option]"
    echo "option: pt,sip,eip,linkTy,sbw,ebw,en,pro,mark"
    echo "eg: $0 '2,192.168.10.102,192.168.10.102,0,128,256,1,1,1'"
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

UPLINK_SPEED=128000
DOWNLINK_SPEED=128000
#echo "$UPLINK_SPEED"
#echo "$DOWNLINK_SPEED"

UplinkList=WiFiDog_${BRIDGE}_Qos_OUT
DownlinkList=WiFiDog_${BRIDGE}_Qos_IN

tmpstr=0
str=$1
echo "$str"


qos_act=`echo $str | cut -f7 -d,`
if [ "$qos_act" == '1' ]; then
    ipt_act=A
	tc_act=add
    #qos_set_num=`expr $qos_set_num + 1`
else
	ipt_act=D
	tc_act=del
	#qos_set_num=`expr $qos_set_num - 1`
fi

tmpstr=`echo $str | cut -f9 -d,`
#echo $tmpstr
wan_pkt_mark=`expr $tmpstr + 63`
lan_pkt_mark=`expr $tmpstr + 83`

mode=`echo $str | cut -f1 -d,`
#mode=2
#echo "$mode"

lo_ip_start=`echo $str | cut -f2 -d,`
#echo "$lo_ip_start"

lo_ip_end=`echo $str | cut -f3 -d,`
#echo "$lo_ip_end"

bandwidth=`echo $str | cut -f5 -d,`
#echo "$bandwidth"

bandwidth_dl=`echo $str | cut -f6 -d,`
#echo "$bandwidth_dl"


if [ "$qos_act" == '1' ]; then
    ## this qos rule is set by IP address            	   	
    IPT_CMD="iptables -$ipt_act $UplinkList -t mangle -m iprange --src-range ${lo_ip_start}-${lo_ip_end} -j MARK --set-mark $wan_pkt_mark"
    echo "$IPT_CMD"
    $IPT_CMD
    
    if [ "$mode" == '1' ]; then
    TC_CMD="tc class $tc_act dev $WAN parent 2:1 classid 2:$wan_pkt_mark htb rate ${bandwidth}kbps ceil ${UPLINK_SPEED}kbps prio 2 quantum 30000"
    else
    TC_CMD="tc class $tc_act dev $WAN parent 2:1 classid 2:$wan_pkt_mark htb rate 1kbps ceil ${bandwidth}kbps prio 2 quantum 30000"
    fi
    echo "$TC_CMD"
    $TC_CMD

    TC_CMD="tc qdisc $tc_act dev $WAN parent 2:$wan_pkt_mark handle 1$wan_pkt_mark: sfq perturb 10"
    echo "$TC_CMD"
    $TC_CMD

    TC_CMD="tc filter $tc_act dev $WAN parent 2:0 protocol ip prio 100 handle $wan_pkt_mark fw classid 2:$wan_pkt_mark"
    echo "$TC_CMD"
    $TC_CMD
    

    IPT_CMD="iptables -$ipt_act $DownlinkList -t mangle -m iprange --dst-range ${lo_ip_start}-${lo_ip_end} -j MARK --set-mark $lan_pkt_mark"
    echo "$IPT_CMD"
    $IPT_CMD
    
    if [ "$mode" == '1' ]; then
    TC_CMD="tc class $tc_act dev $BRIDGE parent 5:1 classid 5:$lan_pkt_mark htb rate ${bandwidth_dl}kbps ceil ${DOWNLINK_SPEED}kbps prio 2 quantum 30000"
    else
    TC_CMD="tc class $tc_act dev $BRIDGE parent 5:1 classid 5:$lan_pkt_mark htb rate 1kbps ceil ${bandwidth_dl}kbps prio 2 quantum 30000"
    fi
    echo "$TC_CMD"
    $TC_CMD

    TC_CMD="tc qdisc $tc_act dev $BRIDGE parent 5:$lan_pkt_mark handle 5$lan_pkt_mark: sfq perturb 10"
    echo "$TC_CMD"
    $TC_CMD

    TC_CMD="tc filter $tc_act dev $BRIDGE parent 5:0 protocol ip prio 100 handle $lan_pkt_mark fw classid 5:$lan_pkt_mark"
    echo "$TC_CMD"
    $TC_CMD
else
    TC_CMD="tc filter $tc_act dev $WAN parent 2:0 protocol ip prio 100 handle $wan_pkt_mark fw classid 2:$wan_pkt_mark"
    echo "$TC_CMD"
    $TC_CMD
    
    TC_CMD="tc qdisc $tc_act dev $WAN parent 2:$wan_pkt_mark handle 1$wan_pkt_mark: sfq perturb 10"
    echo "$TC_CMD"
    $TC_CMD
    
    if [ "$mode" == '1' ]; then
    TC_CMD="tc class $tc_act dev $WAN parent 2:1 classid 2:$wan_pkt_mark htb rate ${bandwidth}kbps ceil ${UPLINK_SPEED}kbps prio 2 quantum 30000"
    else
    TC_CMD="tc class $tc_act dev $WAN parent 2:1 classid 2:$wan_pkt_mark htb rate 1kbps ceil ${bandwidth}kbps prio 2 quantum 30000"
    fi
    echo "$TC_CMD"
    $TC_CMD	    
    
    IPT_CMD="iptables -$ipt_act $UplinkList -t mangle -m iprange --src-range ${lo_ip_start}-${lo_ip_end} -j MARK --set-mark $wan_pkt_mark"
    echo "$IPT_CMD"
    $IPT_CMD
    
    
    TC_CMD="tc filter $tc_act dev $BRIDGE parent 5:0 protocol ip prio 100 handle $lan_pkt_mark fw classid 5:$lan_pkt_mark"
    echo "$TC_CMD"
    $TC_CMD
    
    TC_CMD="tc qdisc $tc_act dev $BRIDGE parent 5:$lan_pkt_mark handle 5$lan_pkt_mark: sfq perturb 10"
    echo "$TC_CMD"
    $TC_CMD
    
    if [ "$mode" == '1' ]; then
    TC_CMD="tc class $tc_act dev $BRIDGE parent 5:1 classid 5:$lan_pkt_mark htb rate ${bandwidth_dl}kbps ceil ${DOWNLINK_SPEED}kbps prio 2 quantum 30000"
    else
    TC_CMD="tc class $tc_act dev $BRIDGE parent 5:1 classid 5:$lan_pkt_mark htb rate 1kbps ceil ${bandwidth_dl}kbps prio 2 quantum 30000"
    fi
    echo "$TC_CMD"
    $TC_CMD
    
    IPT_CMD="iptables -$ipt_act $DownlinkList -t mangle -m iprange --dst-range ${lo_ip_start}-${lo_ip_end} -j MARK --set-mark $lan_pkt_mark"
    echo "$IPT_CMD"
    $IPT_CMD
fi

