#!/bin/bash

#flush iptables
ip6tables -F

#activate forwarding
sysctl -w net/ipv6/conf/all/forwarding=1

#default policy
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT

#forwarding chain
ip6tables -A FORWARD -i eth0 -j ACCEPT
ip6tables -A FORWARD -i eth1 -j ACCEPT
