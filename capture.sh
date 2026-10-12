#!/bin/bash
IFACE=enp0s8
LABEL=$1
OUT=~/ids-project/pcaps_lab/${LABEL}.pcap
FILTER="host 192.168.100.20 or host 192.168.100.30"

if [ -z "$LABEL" ]; then
  echo "Usage: $0 <label>"
  exit 1
fi

echo "Recording -> $OUT"
tcpdump -i "$IFACE" -w "$OUT" $FILTER &
PID=$!
sleep 1
echo "Capturing. Go run the attack on Kali NOW."
read -p "Press ENTER when finished to stop..."
kill -INT "$PID" 2>/dev/null
sleep 1
echo "Saved:"
ls -lh "$OUT"
