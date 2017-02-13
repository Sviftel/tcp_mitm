#!/bin/bash


NS_NAME_PAR="--ns_name"
MID_PORT_PAR="--middle_port"

set_up_ns() {
    local ns_name="$1"
    if [ -z "`ip netns | grep $ns_name`" ]; then
        ip netns add "$ns_name"
    fi

    # bring loopback up
    ip netns exec "$ns_name" ip link set dev lo up
}

add_iptables_rule() {
    local ns_name middle_port
    ns_name="$1"
    middle_port="$2"
    # check and set first iptables rule, for blocking RST from "server"
    RULE="-p tcp --sport ""$middle_port"" --tcp-flags RST RST -j DROP"
    ip netns exec "$ns_name" iptables -C OUTPUT $RULE 2> /dev/null
    if [ "$?" != 0 ]; then
        ip netns exec "$ns_name" iptables -A OUTPUT $RULE
    fi
}

print_help() {
    local usage
    usage="Usage: ./ns_setup.sh ""$NS_NAME_PAR"" <namespace_name> ""$MID_PORT_PAR"" <port_number>"
    echo "$usage"
}

if [ "$#" != "4" ]; then
    print_help
    exit 1
fi

while [ "$#" -gt "0" ]; do
    case $1 in
        "$NS_NAME_PAR")
            shift
            ns_name="$1"
            shift
            ;;
        "$MID_PORT_PAR")
            shift
            mid_port="$1"
            if ! [[ "$mid_port" =~ [1-5][0-9]{4} ]]; then
                echo "port must be in numbers, from 10000 to 59999!"
                exit 1
            fi
            shift
            ;;
        "help")
            print_help
            exit 0
            ;;
        *)
            print_help
            exit 1
            ;;
    esac
done

set_up_ns "$ns_name"
add_iptables_rule "$ns_name" "$mid_port"
