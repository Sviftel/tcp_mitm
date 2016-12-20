#!/bin/sh


NS_NAME=test_ns

if [ -z "`ip netns | grep $NS_NAME`" ]; then
    ip netns add $NS_NAME
fi

# bring loopback up
ip netns exec test_ns ip link set dev lo up

# check and set first iptables rule, for blocking RST from "server"
RULE="-p tcp --sport 10020 --tcp-flags RST RST -j DROP"
ip netns exec test_ns iptables -C OUTPUT $RULE 2> /dev/null
if [ "$?" != 0 ]; then
    ip netns exec test_ns iptables -A OUTPUT $RULE
fi
