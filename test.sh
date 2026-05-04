#!/bin/bash
set -x

iptables -F
iptables -A OUTPUT -j NFQUEUE --queue-num 0
iptables -A INPUT  -j NFQUEUE --queue-num 0

./1m-block top-1m.csv &
sleep 2
PID=$(pidof 1m-block)

top -bn1 -p $PID

wget --tries=1 --timeout=3 -O /dev/null http://httpforever.com
wget --tries=1 --timeout=3 -O /dev/null http://google.com

kill $PID
iptables -F
