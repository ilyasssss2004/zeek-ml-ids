#!/bin/bash
PCAP_DIR=~/ids-project/pcaps_lab
OUT_DIR=~/ids-project/zeek_out/lab

for pcap in "$PCAP_DIR"/*.pcap; do
  name=$(basename "$pcap" .pcap)
  mkdir -p "$OUT_DIR/$name"
  cd "$OUT_DIR/$name"
  zeek -C -r "$pcap" \
    ~/zeek-ml/tools/zeek-flowmeter/scripts/__load__.zeek \
    policy/tuning/json-logs
  echo "$name: $(wc -l < flowmeter.log 2>/dev/null || echo 0) flows"
  cd ~/ids-project
done
