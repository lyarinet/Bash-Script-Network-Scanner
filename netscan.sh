#!/bin/bash

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
NC="\033[0m"

# Check dependencies
check_dependencies() {
  echo -e "${CYAN}Checking dependencies...${NC}"
  for cmd in nmap tcpdump perl jq parallel smbclient; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      if [ "$cmd" = "parallel" ]; then
        echo -e "${RED}Error:${NC} GNU Parallel is not installed."
        echo -e "${YELLOW}Install it using:${NC} sudo apt install parallel"
        exit 1
      elif [ "$cmd" = "smbclient" ]; then
        echo -e "${YELLOW}smbclient not found. Installing...${NC}"
        apt update && apt install -y smbclient || {
          echo -e "${RED}Failed to install smbclient${NC}"
          exit 1
        }
      else
        echo -e "${RED}Error:${NC} $cmd is not installed."
        exit 1
      fi
    fi
  done
}

# Ensure script is run as root
check_root() {
  if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Run as root or with sudo${NC}"
    exit 1
  fi
}

# Get interfaces
get_interfaces() {
  echo -e "${CYAN}Available interfaces:${NC}"
  mapfile -t iface_list < <(ip -o link show | awk -F': ' '{print $2}' | grep -v lo)
  for i in "${!iface_list[@]}"; do
    printf "[%d] %s\n" "$((i+1))" "${iface_list[$i]}"
  done
  printf "[%d] all\n" "$(( ${#iface_list[@]} + 1 ))"

  read -p "Choose interface [1-${#iface_list[@]} or all]: " choice
  interfaces=()
  max_choice=$(( ${#iface_list[@]} + 1 ))

  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#iface_list[@]} )); then
    interfaces=("${iface_list[$((choice-1))]}")
  elif [[ "$choice" == "all" ]] || (( choice == max_choice )); then
    interfaces=("${iface_list[@]}")
  else
    echo -e "${RED}Invalid choice.${NC}"
    exit 1
  fi

  echo
  for iface in "${interfaces[@]}"; do
    ip_address=$(ip -o -f inet addr show "$iface" | awk '{print $4}')
    echo -e "${YELLOW}Selected interface:${NC} $iface ${ip_address:+(IP: $ip_address)}"
  done
  echo
}

# Choose scan type
choose_scan_type() {
  echo -e "\n${CYAN}Choose scan type:${NC}"
  echo "1) Standard (ping + nbstat)"
  echo "2) UDP port scan (top 1000)"
  echo "3) Listen for UDP multicast"
  read -p "Choice [1-3]: " scan_type
}

# Multicast scan
multicast_scan() {
  read -p "Duration for multicast sniff (seconds, default 30): " duration
  duration=${duration:-30}
  for iface in "${interfaces[@]}"; do
    echo -e "${CYAN}Listening on $iface...${NC}"
    timeout "$duration" tcpdump -i "$iface" -n multicast 2>/dev/null | \
      perl -n -e 'chomp; m/> (\d+\.\d+\.\d+\.\d+)\.(\d+)/; print "udp://$1:$2\n" if $1 && $2' | \
      sort | uniq | tee "multicast_$iface.log"
  done
  echo -e "${GREEN}Multicast capture saved to multicast_<iface>.log${NC}"
  exit 0
}

# Scan single host
scan_host() {
  local IP="$1"
  local udp="$2"
  local output MAC HOSTNAME WG_DOMAIN MANUFACTURER SHARES

  if [ "$udp" = "true" ]; then
    echo -e "\n${YELLOW}UDP Scan: $IP${NC}"
    nmap -sU --top-ports 1000 "$IP"
    return
  fi

  output=$(nmap --script nbstat.nse -p 137,139 "$IP")
  MAC=$(echo "$output" | grep 'MAC Address' | awk '{print $3}')
  HOSTNAME=$(echo "$output" | grep '<20>.*<unique>.*<active>' | awk -F'[|<]' '{print $2}' | tr -d '_' | xargs)
  WG_DOMAIN=$(echo "$output" | grep -v '<permanent>' | grep '<00>.*<group>.*<active>' | awk -F'[|<]' '{print $2}' | tr -d '_' | xargs)
  MANUFACTURER=$(echo "$output" | grep 'MAC Address' | awk -F'(' '{print $2}' | cut -d ')' -f1)

  if nc -z -w1 "$IP" 445 2>/dev/null; then
    smbclient_output=$(smbclient -L "//$IP" -N 2>/dev/null)
    SHARES=$(echo "$smbclient_output" | awk '/Disk/ && !/IPC/ {print $1}' | paste -sd "," -)
  else
    SHARES=""
  fi

  local lease_file="/var/lib/dhcp/dhcpd.leases"
  if [ -f "$lease_file" ] && [ -z "$HOSTNAME" ]; then
    HOSTNAME=$(awk -v ip="$IP" '$1 == "lease" && $2 == ip {f=1} f && /client-hostname/ {print substr($2, 2, length($2) - 3); exit}' "$lease_file" | cut -c 1-15)
    [ -n "$HOSTNAME" ] && HOSTNAME="$HOSTNAME *"
  fi

  printf "%-14s | %-17s | %-17s | %-15s | %-20s | %-30s\n" "$IP" "$MAC" "$HOSTNAME" "$WG_DOMAIN" "$SHARES" "$MANUFACTURER"
  echo "$IP,$MAC,$HOSTNAME,$WG_DOMAIN,$SHARES,$MANUFACTURER" >> scan_results.csv
  echo "{\"ip\":\"$IP\",\"mac\":\"$MAC\",\"hostname\":\"$HOSTNAME\",\"wg_domain\":\"$WG_DOMAIN\",\"shares\":\"$SHARES\",\"manufacturer\":\"$MANUFACTURER\"}," >> scan_results.json.tmp
}

# Perform scan
perform_scan() {
  udp_scan=false
  [ "$scan_type" == "2" ] && udp_scan=true

  declare -a all_ips
  for iface in "${interfaces[@]}"; do
    ip_range=$(ip -o -f inet addr show "$iface" | awk '{print $4}' | sed 's/\.[0-9]*\//.0\//')
    [ -z "$ip_range" ] && echo -e "${YELLOW}Skipping $iface${NC}" && continue
    echo -e "${CYAN}Scanning $ip_range...${NC}"
    mapfile -t iface_ips < <(nmap -sn "$ip_range" | awk '/Nmap scan report/{gsub(/[()]/,"",$NF); print $NF}')
    all_ips+=("${iface_ips[@]}")
  done

  IFS=$'\n' read -r -d '' -a ips < <(printf "%s\n" "${all_ips[@]}" | sort -u && printf '\0')

  echo "IP,MAC,HOSTNAME,WG_DOMAIN,SHARES,MANUFACTURER" > scan_results.csv
  echo "[" > scan_results.json.tmp

  echo -e "\n${CYAN}Results:${NC}"
  printf "%-14s | %-17s | %-17s | %-15s | %-20s | %-30s\n" "IP" "MAC" "HOSTNAME" "WG/DOMAIN" "SHARES" "MANUFACTURER"
  printf "%s\n" "$(printf '%0.s-' {1..120})"

  export -f scan_host
  parallel -j4 scan_host ::: "${ips[@]}" ::: "$udp_scan"

  sed -i '$ s/},/}/' scan_results.json.tmp
  echo "]" >> scan_results.json.tmp
  mv scan_results.json.tmp scan_results.json

  echo -e "\n${GREEN}Scan complete.${NC} Results saved to:"
  echo -e "  - ${YELLOW}scan_results.csv${NC}"
  echo -e "  - ${YELLOW}scan_results.json${NC}"
}

### Main ###
check_dependencies
check_root
get_interfaces
choose_scan_type
[ "$scan_type" == "3" ] && multicast_scan
perform_scan
