#!/bin/bash


ns_name="test_ns"
middle_port=10020
server_port=20040


./ns_managing/setup.sh --ns_name "$ns_name" --middle_port "$middle_port"
ip netns exec "$ns_name" ./sample_usage.py --server_port "$server_port" --middle_port "$middle_port"
./ns_managing/teardown.sh "$ns_name"
