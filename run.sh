#!/bin/bash


ns_name="test_ns"
middle_port=10020
server_port=20040

if [ "$#" -le "0" ]; then
    echo "Provide a script to run within network namespace: ""$0"" <script>"
    exit 1
fi

script_name="$1"

./ns_managing/setup.sh --ns_name "$ns_name" --middle_port "$middle_port"
ip netns exec "$ns_name" ./"$script_name" --server_port "$server_port" --middle_port "$middle_port"
./ns_managing/teardown.sh "$ns_name"
