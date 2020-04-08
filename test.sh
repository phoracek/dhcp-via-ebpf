#!/usr/bin/bash -xe
ip link add v_client type veth peer name v_server || true
ip link set v_client up || true
ip link set v_server up || true
killall dhclient || true
sleep 1
python main.py v_server &
dhclient v_client -v --timeout 30
