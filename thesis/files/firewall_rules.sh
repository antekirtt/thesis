#!/bin/bash

#define in out variables
INSIDEIF=eth0
INSIDENET=2001:abcd:acad:2::1/64
OUTSIDEIF=eth1
OUTSIDENET=2001:abcd:acad:1::1/64

#activate forwarding
sysctl -w net/ipv6/conf/all/forwarding=1

#clean all
ip6tables -F
ip6tables -X ICMPV6-TO-OUT
ip6tables -X ICMPV6-TO-IN
ip6tables -X SSH-IN
ip6tables -X SSH-OUT
ip6tables -Z

#create ad hoc chains
ip6tables -N ICMPV6-TO-OUT
ip6tables -N ICMPV6-TO-IN
ip6tables -N SSH-IN
ip6tables -N SSH-OUT

#default policy is to drop (whitelist approach)
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP

#loopback traffic is accepted
ip6tables -A INPUT -s ::1 -d ::1 -j ACCEPT

#accept new ssh traffic on internal interface and network only
ip6tables -A INPUT -i $INSIDEIF -s $INSIDENET -p tcp --dport 22 -m state --state NEW -j ACCEPT
#accept established and related traffic on all interfaces
ip6tables -A INPUT -p tcp --dport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT
#accept ndp messages directed to the router/firewall (this is needed because of the policy)
ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type redirect -j ACCEPT



#accept ssh related and established traffic, and ns,na traffic on output chain
ip6tables -A OUTPUT -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT
ip6tables -A OUTPUT -j LOG --log-prefix "output drops"
ip6tables -A OUTPUT -j DROP

#drop icmpv6 packets with link-local src/dst address in forwarding chain
ip6tables -A FORWARD -p icmpv6 -d fe80::/10 -j DROP
ip6tables -A FORWARD -p icmpv6 -s fe80::/10 -j DROP
#drop echo reply with dst multicast address in forwarding chain
ip6tables -A FORWARD -p icmpv6 -d ff00::/8 --icmpv6-type echo-reply -j DROP

#icmpv6 traffic from internal to be forwarded to external
ip6tables -A FORWARD -s $INSIDENET -d $OUTSIDENET -p icmpv6 -j ICMPV6-TO-OUT
#ssh traffic from internal to be forwarded to external
ip6tables -A FORWARD -i $INSIDEIF -o $OUTSIDEIF -s $INSIDENET -d $OUTSIDENET -p tcp --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j SSH-OUT

#icmpv6 traffic from external to be forwarded to internal
ip6tables -A FORWARD -d $INSIDENET -p icmpv6 -j ICMPV6-TO-IN
#ssh traffic from external to be forwarded to internal
ip6tables -A FORWARD -d $INSIDENET -p tcp --sport 22 -m state --state ESTABLISHED,RELATED -j SSH-IN
ip6tables -A FORWARD -j LOG --log-prefix "FORWARDING DROPS"

#---------------------------------
#forwarding rules from IN to OUT -
#---------------------------------

#accept ssh to be forwarded to external network
ip6tables -A SSH-OUT -i $INSIDEIF -o $OUTSIDEIF -s $INSIDENET -d $OUTSIDENET -p tcp --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#accept error messages
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
#echo request  with rate limit
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type echo-request -m limit --limit 900/min -j ACCEPT
#echo reply is dropped because of internal policy
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type echo-reply -j DROP
#NDP messages only if they haven't traversed a router (this is to underline the required hop limit of 255)
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type router-advertisement -m hl --hl-eq 255 -j ACCEPT
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type neighbor-solicitation -m hl --hl-eq 255 -j ACCEPT
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type neighbor-advertisement -m hl --hl-eq 255 -j ACCEPT
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 --icmpv6-type redirect -m hl --hl-eq 255 -j ACCEPT
#drop remaining icmpv6 packets (for clarity, but redundant because of the policy)
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 -j LOG --log-prefix "Firewall IN-OUT: dropped ICMPv6"
ip6tables -A ICMPV6-TO-OUT -s $INSIDENET -d $OUTSIDENET -p icmpv6 -j DROP

#--------------------------------
#forwarding rule from OUT to IN -
#--------------------------------

#accept established and related ssh to be forwarded to internal network
ip6tables -A SSH-IN -d $INSIDENET -p tcp --sport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT
#accept error messages ---- TODO: evaluate if it is worth to use state for error msg, and only dst addresses
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
#echo request and reply , no ping from outside (internal policy), but allow reply to come back with rate limit
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type echo-request -j DROP
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type echo-reply -m limit --limit 900/min -j ACCEPT
#drop explicitly and log ndp messages
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type router-advertisement -j LOG --log-prefix "Firewall OUT-IN: dropped ra"
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type router-solicitation -j LOG --log-prefix "Firewall OUT-IN: dropped rs"
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type neighbor-advertisement -j LOG --log-prefix "Firewall OUT-IN: dropped na"
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type neighbor-solicitation -j LOG --log-prefix "Firewall OUT-IN: dropped ns"
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type redirect -j LOG --log-prefix "Firewall OUT-IN: dropped redirect"
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type router-advertisement -j DROP
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type router-solicitation -j DROP
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type neighbor-advertisement -j DROP
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type neighbor-solicitation -j DROP
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 --icmpv6-type redirect -j DROP
ip6tables -A ICMPV6-TO-IN -d $INSIDENET -p icmpv6 -j DROP


