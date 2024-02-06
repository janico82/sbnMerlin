#!/bin/sh

#############################################################
##            _           __  __           _ _             ##
##        ___| |__  _ __ |  \/  | ___ _ __| (_)_ __        ##
##       / __| '_ \| '_ \| |\/| |/ _ \ '__| | | '_ \       ##
##       \__ \ |_) | | | | |  | |  __/ |  | | | | | |      ##
##       |___/_.__/|_| |_|_|  |_|\___|_|  |_|_|_| |_|      ##
##                                                         ##
##          https://github.com/janico82/sbnMerlin          ##
##                                                         ##
#############################################################
##   Credit to Renjie Wu for the LAN port isolation post   ##
##           and to @jackyaz for the YazFi script          ##
##         to @RMerlin for AsusWRT-Merlin firmware.        ##
#############################################################
# Last Modified: janico82 [2024-Feb-06].
#--------------------------------------------------

# Shellcheck directives #
# shellcheck disable=SC1087
# shellcheck disable=SC1090
# shellcheck disable=SC2005
# shellcheck disable=SC2016
# shellcheck disable=SC2034
# shellcheck disable=SC2086
# shellcheck disable=SC2129
# shellcheck disable=SC2317
# shellcheck disable=SC3045

# Script variables #
readonly script_name="sbnMerlin"
readonly script_dir="/jffs/addons/$script_name.d"
readonly script_cdir="/jffs/addons/$script_name.d/cscripts"
readonly script_xdir="/jffs/scripts"
readonly script_diag="/tmp/$script_name"
readonly script_config="$script_dir/$script_name.conf"
readonly script_md5="$script_dir/$script_name.md5"
readonly script_version="1.0.1"
readonly script_branch="master"
readonly script_repo="https://janico82.gateway.scarf.sh/asuswrt-merlin/$script_name/$script_branch"

readonly log_file="$script_dir/$script_name.log"
readonly log_size=5120 # 5MB in kilobytes
readonly log_rotation=5 # Maximum number of log files to keep

# Script environment variables 
readonly env_allowedbridges="br3 br4 br5 br6 br8 br9" # br1 & br2 are router default bridges, so br7 is not allowed
readonly env_error=127
readonly env_restart=1
readonly env_no_restart=0
readonly env_enable=1
readonly env_disable=0
readonly env_regex_version="[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})"
readonly env_regex_binary="[01]"
readonly env_regex_bridge="br[0-9]+"
readonly env_regex_allowed_bridge="br[345689]+"
readonly env_regex_eth_ifname="(eth[1-9]+)"
readonly env_regex_wl_ifname="(wl[0-1]+(\.[1-3]+))"
readonly env_regex_allowed_ifname="($env_regex_eth_ifname|$env_regex_wl_ifname)"
readonly env_regex_ipaddr="(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
readonly env_regex_local_ipaddr="(^10\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(^192\.168\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$"
readonly env_regex_macaddr="([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
readonly env_regex_netmask="(255)\.(0|128|192|224|240|248|252|254|255)\.(0|128|192|224|240|248|252|254|255)\.(0|128|192|224|240|248|252|254)"
readonly env_regex_netname="[a-zA-Z][a-zA-Z0-9_-]{0,19}"
readonly env_regex_number="[0-9]+"
readonly env_file_srv_start="/jffs/scripts/services-start"
readonly env_file_srv_end="/jffs/scripts/service-event-end"
readonly env_file_fw_start="/jffs/scripts/firewall-start"
readonly env_file_avahi_pc="/jffs/scripts/avahi-daemon.postconf"
readonly env_file_dnsmasq_pc="/jffs/scripts/dnsmasq.postconf"
readonly env_file_hosts_pc="/jffs/scripts/hosts.postconf"

loggerEx() {

	# Send output messages to syslog and logfie by default or cli. Usage: loggerEx "Script in use"
	mtype="$(if [ $# -eq 1 ]; then echo "default"; else echo "$1"; fi)"
	message="$(if [ $# -eq 1 ]; then echo "$1"; else echo "$2"; fi)"
	pid="$(echo $$ | awk -F. '{ printf("%05d", $1); }')"
	
	if [ "$mtype" = "default" ] || [ "$mtype" = "cli" ]; then
		# Send output messages to syslog
		logger -t "$script_name[$pid]" "$message"

		# Send output messages to logfile
		echo "$(date) [PID:$pid] " "$message" >> "$log_file"

		# Check if log file exceeds the maximum size and rotate if necessary
		if [ "$log_size" -lt "$(du -k "$log_file" | awk '{print $1}')" ]; then

			# Create a new log file with a timestamp
			mv "$log_file" "${log_file}_$(date +'%Y%m%d')"

			# Delete old log files exceeding the maximum limit
			log_files=$(ls -t "$script_dir"/*.log_*)
			num_logfiles=$(echo "$log_files" | wc -l)

			if [ "$num_logfiles" -gt "$log_rotation" ]; then
				old_logfile=$(echo "$log_files" | tail -n 1)
				rm "$script_dir/$old_logfile"
			fi
		fi
	fi

	# Send output message to cli
	if [ "$mtype" = "cli" ] || [ "$mtype" = "clio" ] ; then
		printf "%s\\n\\n" "$message"
	fi
}

compare_ssid() {

	# Confirm the ssid are equal. Usage: compare_ssid wl0.2 wl1.2
	if [ $# -ne 2 ] || [ "$(nvram get "${1}_ssid")" != "$(nvram get "${2}_ssid")" ]; then
		return $env_error # NOK or the ssid are not equal
	else 
		return 0 # The ssid are equal
	fi
}

validate_binary() {

	# Confirm the value is binary. Usage: validate_binary 1
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "^$env_regex_binary$" ; then
		return $env_error # NOK
	else
		return 0 # OK
	fi	
}

validate_bridge() {

	# Confirm the bridge name is valid. Usage: validate_bridge br8
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "^$env_regex_allowed_bridge$" ; then
		return $env_error # NOK
	else
		return 0 # OK
	fi
}

validate_ifname() {

	# Confirm the interface name is valid. Usage: validate_ifname wl0.1
	if [ "$#" -ne 1 ] || ! echo "$1" | grep -qE "^$env_regex_allowed_ifname$" ; then
		return $env_error # NOK
	else
		return 0 # OK
	fi
}

validate_ifnames() {

	# Confirm the interface names are valid. Usage: validate_ifnames wl0.1 wl1.1
	for if_name in $1; do

		if ! validate_ifname "$if_name" ; then
			return $env_error # NOK
		fi
	done

	return 0 # OK
}

validate_ipaddr() {

	# Confirm the ip address is valid. Usage: validate_ipaddr 192.168.108.1
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "^$env_regex_ipaddr$" ; then
		return $env_error # NOK or not valid 
	else
		return 0 # OK
	fi
}

validate_local_ipaddr() {

	# Confirm the ip address is valid. Usage: validate_local_ipaddr 192.168.108.1
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "$env_regex_local_ipaddr" ; then
		return $env_error # NOK or not valid 
	else
		return 0 # OK
	fi
}

validate_macaddr() {

	# Confirm the mac address is valid. Usage: validate_macaddr 00:00:00:00:00:00
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "^$env_regex_macaddr$" ; then
		return $env_error # NOK or not valid 
	else
		return 0 # OK
	fi
}

validate_netmask() {

	# Confirm the network mask address is valid. Usage: validate_netmask 255.255.255.0
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "^$env_regex_netmask$" ; then
		return $env_error # NOK or not valid 
	else
		return 0 # OK
	fi
}

validate_netname() {

	# Confirm the computer name is valid. Usage: validate_netname CARVAHALL
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "^$env_regex_netname$" ; then
		return $env_error # NOK or not valid 
	else
		return 0 # OK
	fi
}

validate_number() {

	# Confirm the value is valid. Usage: validate_number 32
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "^$env_regex_number$" ; then
		return $env_error # NOK or not valid 
	else
		return 0 # OK
	fi
}

convert_cidr() {
	netmask=$1

	netparts=$(echo "$netmask" | tr '.' ' ')

	cidr=0
	for p in $netparts; do
		pdecimal=$(echo "$p" | awk '{ printf "%d\n", $0 }')
		while [ "$pdecimal" -gt 0 ]; do
			cidr=$((cidr + 1))
			pdecimal=$((pdecimal & (pdecimal - 1)))
		done
	done

	echo $cidr # OK
}

convert_netaddr() {
    ipaddr=$1
    netmask=$2

	ipparts=$(echo "$ipaddr" | tr '.' ' ')
	netparts=$(echo "$netmask" | tr '.' ' ')

    ippart1=$(echo "$ipparts" | awk '{print $1}')
    ippart2=$(echo "$ipparts" | awk '{print $2}')
    ippart3=$(echo "$ipparts" | awk '{print $3}')
    ippart4=$(echo "$ipparts" | awk '{print $4}')

    netpart1=$(echo "$netparts" | awk '{print $1}')
    netpart2=$(echo "$netparts" | awk '{print $2}')
    netpart3=$(echo "$netparts" | awk '{print $3}')
    netpart4=$(echo "$netparts" | awk '{print $4}')

    network_address="$((ippart1 & netpart1)).$((ippart2 & netpart2)).$((ippart3 & netpart3)).$((ippart4 & netpart4))"

    echo "$network_address/$(convert_cidr "$netmask")"
}

getconf_bri_allow_internet() {

	# Get config settings from nvram, if exists
	bri_allow_internet="$(nvram get "${1}_allow_internet")"

	# Get config settings from file, if exists
	if { [ -z "$bri_allow_internet" ] || [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_allow_internet="$(eval echo '$'"${1}_allow_internet")"
	fi

	# Get defaults
	if [ -z $bri_allow_internet ] || ! validate_binary "$bri_allow_internet" ; then
		bri_allow_internet=$env_disable
		loggerEx "Error: Invalid configuration gathered, using defaults($bri_allow_internet)."
	fi

	echo $bri_allow_internet
}

getconf_bri_allow_onewayaccess() {

	# Get config settings from nvram, if exists
	bri_allow_onewayaccess="$(nvram get "${1}_allow_onewayaccess")"

	# Get config settings from file, if exists
	if { [ -z "$bri_allow_onewayaccess" ] || [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_allow_onewayaccess="$(eval echo '$'"${1}_allow_onewayaccess")"
	fi

	# Get defaults
	if [ -z $bri_allow_onewayaccess ] || ! validate_binary "$bri_allow_onewayaccess" ; then
		bri_allow_onewayaccess=$env_disable
		loggerEx "Error: Invalid configuration gathered, using defaults($bri_allow_onewayaccess)."
	fi

	echo $bri_allow_onewayaccess
}

getconf_bri_ap_isolate() {

	# Get config settings from nvram, if exists
	bri_ap_isolate="$(nvram get "${1}_ap_isolate")"

	# Get config settings from file, if exists
	if { [ -z "$bri_ap_isolate" ] || [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_ap_isolate="$(eval echo '$'"${1}_ap_isolate")"
	fi

	# Get defaults
	if [ -z $bri_ap_isolate ] || ! validate_binary "$bri_ap_isolate" ; then
		bri_ap_isolate=$env_disable
		loggerEx "Error: Invalid configuration gathered, using defaults($bri_ap_isolate)."
	fi

	echo $bri_ap_isolate
}

getconf_bri_enabled() {

	# Get config settings from nvram, if exists
	bri_enabled="$(nvram get "${1}_enabled")"

	# Get config settings from file, if exists
	if { [ -z "$bri_enabled" ] || [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_enabled="$(eval echo '$'"${1}_enabled")"
	fi

	# Get defaults
	if [ -z $bri_enabled ] || ! validate_binary "$bri_enabled" ; then
		bri_enabled=$env_disable
		loggerEx "Error: Invalid configuration gathered, using defaults($bri_enabled)."
	fi

	echo $bri_enabled
}

getconf_bri_dhcp_start() {

	# Get config settings from nvram, if exists
	bri_dhcp_start="$(nvram get "${1}_dhcp_start")"

	# Get config settings from file, if exists
 	if { [ -z "$bri_dhcp_start" ]|| [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_dhcp_start="$(eval echo '$'"${1}_dhcp_start")"
	fi
	
	# Get defaults
	if [ -z "$bri_dhcp_start" ] || ! validate_local_ipaddr "$bri_dhcp_start" ; then

		case $1 in
			# br1) bri_dhcp_start="192.168.101.2" ;;	#do not use. leave default
			# br2) bri_dhcp_start="192.168.102.2" ;;	#do not use. leave default
			br3) bri_dhcp_start="192.168.103.2" ;;
			br4) bri_dhcp_start="192.168.104.2" ;;
			br5) bri_dhcp_start="192.168.105.2" ;;
			br6) bri_dhcp_start="192.168.106.2" ;;
			# br7) bri_dhcp_start="192.168.107.2" ;;	#do not use while defaults
			br8) bri_dhcp_start="192.168.108.2" ;;
			br9) bri_dhcp_start="192.168.109.2" ;;
		esac

		loggerEx "Error: Invalid DHCPv4 address gathered from config, using defaults($bri_dhcp_start)."
	fi

	echo "$bri_dhcp_start"
}

getconf_bri_dhcp_end() {

	# Get config settings from nvram, if exists
	bri_dhcp_end="$(nvram get "${1}_dhcp_end")"

	# Get config settings from file, if exists
 	if { [ -z "$bri_dhcp_end" ]|| [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_dhcp_end="$(eval echo '$'"${1}_dhcp_end")"
	fi
	
	# Get defaults
	if [ -z "$bri_dhcp_end" ] || ! validate_local_ipaddr "$bri_dhcp_end" ; then

		case $1 in
			# br1) bri_dhcp_end="192.168.101.254" ;;	#leave default
			# br2) bri_dhcp_end="192.168.102.254" ;;	#leave default
			br3) bri_dhcp_end="192.168.103.254" ;;
			br4) bri_dhcp_end="192.168.104.254" ;;
			br5) bri_dhcp_end="192.168.105.254" ;;
			br6) bri_dhcp_end="192.168.106.254" ;;
			# br7) bri_dhcp_end="192.168.107.254" ;;	#do not use while defaults
			br8) bri_dhcp_end="192.168.108.254" ;;
			br9) bri_dhcp_end="192.168.109.254" ;;
		esac

		loggerEx "Error: Invalid DHCPv4 address gathered from config, using defaults($bri_dhcp_end)."
	fi

	echo "$bri_dhcp_end"
}

getconf_bri_ifnames() {

	# Get config settings from nvram, if exists
	bri_ifnames="$(nvram get "${1}_ifnames")"

	# Get config settings from file, if exists
 	if { [ -z "$bri_ifnames" ] || [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_ifnames="$(eval echo '$'"${1}_ifnames")"
	fi
	
	# Confirm if the ifnames are valid, if not add defaults
	if [ -z "$bri_ifnames" ] || ! validate_ifnames "$bri_ifnames" ; then
		bri_ifnames=""
		loggerEx "Error: Invalid interfaces gathered from config, using defaults($bri_ifnames)."
	fi

	# Add script default ifnames and remove duplicates
	case $1 in
		# br1) bri_ifnames=$(echo "${bri_ifnames} wl0.1" | tr ' ' '\n' | sort -u) ;;	#leave default
		# br2) bri_ifnames=$(echo "${bri_ifnames} wl1.1" | tr ' ' '\n' | sort -u) ;;	#leave default
		br3) bri_ifnames=$(echo "${bri_ifnames} wl0.2" | tr ' ' '\n' | sort -u) ;;
		br4) bri_ifnames=$(echo "${bri_ifnames} wl1.2" | tr ' ' '\n' | sort -u) ;;
		br5) bri_ifnames=$(echo "${bri_ifnames} wl0.3" | tr ' ' '\n' | sort -u) ;;
		br6) bri_ifnames=$(echo "${bri_ifnames} wl1.3" | tr ' ' '\n' | sort -u) ;;
		# br7) bri_ifnames=$(echo "${bri_ifnames} wl0.1 wl1.1" | tr ' ' '\n' | sort -u) ;;	#leave default
		br8) bri_ifnames=$(echo "${bri_ifnames} wl0.2 wl1.2" | tr ' ' '\n' | sort -u) ;;
		br9) bri_ifnames=$(echo "${bri_ifnames} wl0.3 wl1.3" | tr ' ' '\n' | sort -u) ;;
	esac

	# Join the elements of the merged array back into a single string and remove leading and trailing whitespace
	bri_ifnames=$(echo "$bri_ifnames" | tr '\n' ' ' | xargs)

	echo "$bri_ifnames"
}

getconf_bri_ipaddr() {

	# Get config settings from nvram, if exists
	bri_ipaddr="$(nvram get "${1}_ipaddr")"

	# Get config settings from file, if exists
 	if { [ -z "$bri_ipaddr" ] || [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_ipaddr="$(eval echo '$'"${1}_ipaddr")"
	fi
	
	# Get defaults
	if [ -z "$bri_ipaddr" ] || ! validate_local_ipaddr "$bri_ipaddr" ; then

		case $1 in
			# br1) bri_ipaddr="192.168.101.1" ;;	#leave default
			# br2) bri_ipaddr="192.168.102.1" ;;	#leave default
			br3) bri_ipaddr="192.168.103.1" ;;
			br4) bri_ipaddr="192.168.104.1" ;;
			br5) bri_ipaddr="192.168.105.1" ;;
			br6) bri_ipaddr="192.168.106.1" ;;
			# br7) bri_ipaddr="192.168.107.1" ;;	#leave default
			br8) bri_ipaddr="192.168.108.1" ;;
			br9) bri_ipaddr="192.168.109.1" ;;
		esac

		loggerEx "Error: Invalid IP address gathered from config, using defaults($bri_ipaddr)."
	fi

	echo "$bri_ipaddr"
}

getconf_bri_netmask() {

	# Get config settings from nvram, if exists
	bri_netmask="$(nvram get "${1}_netmask")"

	# Get config settings from file, if exists
 	if { [ -z "$bri_netmask" ] || [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_netmask="$(eval echo '$'"${1}_netmask")"
	fi
	
	# Get defaults
	if [ -z "$bri_netmask" ] || ! validate_netmask "$bri_netmask" ; then

		bri_netmask="255.255.255.0"

		loggerEx "Error: Invalid network mask gathered from config, using defaults($bri_netmask)."
	fi

	echo "$bri_netmask"
}

getconf_bri_staticlist() {

	# Get config settings from nvram, if exists
	bri_staticlist="$(nvram get "${1}_staticlist")"

	# Get config settings from file, if exists
 	if { [ -z "$bri_staticlist" ] || [ "$2" = "sc" ]; } && [ -f $script_config ]; then

		. $script_config
		bri_staticlist="$(eval echo '$'"${1}_staticlist")"
	fi
	
	# Validate config values
	for static in $(echo "${bri_staticlist#<}" | tr '<' ' '); do

		macaddr=$(echo "$static" | awk -F'[<>]' '{print $1}')
		ipaddr=$(echo "$static" | awk -F'[<>]' '{print $2}')
		netname=$(echo "$static" | awk -F'[<>]' '{print $NF}')

		if ! validate_macaddr "$macaddr" || ! validate_ipaddr "$ipaddr" || { [ -n "$netname" ] && ! validate_netname "$netname" ; }; then

			unset bri_staticlist
			loggerEx "Error: Invalid static list gathered from config."

			break
		fi
	done

	echo "$bri_staticlist"
}

getconf_lan_domain() {

	# Get config settings from nvram, if exists
	echo "$(nvram get lan_domain)"
}

getconf_lan_hostname() {

	# Get config settings from nvram, if exists
	echo "$(nvram get lan_hostname)"
}

getconf_lan_fqn_hostname() {

	lan_domain=$(getconf_lan_domain)
	lan_hostname=$(getconf_lan_hostname)

	if [ -n "$lan_domain" ]; then lan_hostname="$lan_hostname.$lan_domain"; fi

	echo $lan_hostname
}

gethw_bri_enabled() {

	# Get list of ative bridges. Usage: gethw_bri_enabled 
	echo "$(ip -o link show type bridge | grep -o -E '\b'"$env_regex_allowed_bridge"'\b' | tr '\n' ' ' | xargs)"
}

gethw_bri_ifnames() {

	# Get list of interfaces from bridge. Usage: gethw_bri_ifnames br8
	echo "$(brctl show "$1" | awk 'NR>1' | awk '{print $NF}' | grep -o -E '\b'"$env_regex_allowed_ifname"'\b' | tr '\n' ' ' | xargs)"
}

gethw_if_enabled() {

	# Get list of ative interfaces. Usage: gethw_if_enabled 
	echo "$(ip -o link show | grep -o -E '\b'"$env_regex_allowed_ifname"'\b' | tr '\n' ' ' | xargs)"
}

gethw_if_bridge() {

	# Get bridge from a given interface. Usage: gethw_if_bridge wl0.1
	echo "$(ip -o link show "$1" | grep -o -E '\b'"$env_regex_bridge"'\b')"
}

evfile_firewall_start() {
	evfile=$env_file_fw_start

	# Confirm the event files are created. Usage evfile_firewall_start create
	case $1 in
		create)
			
			if [ -f "$evfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$evfile")
				filelinecountex=$(grep -cx "$script_xdir/$script_name run-firewall & # ($script_name) Network Isolation Tool" "$evfile")
				
				if [ "$filelinecount" -gt 1 ] || { [ "$filelinecountex" -eq 0 ] && [ "$filelinecount" -gt 0 ]; }; then
					sed -i -e '/# ('"$script_name"')/d' "$evfile"
				fi
				
				if [ "$filelinecountex" -eq 0 ]; then
					echo "$script_xdir/$script_name run-firewall & # ($script_name) Network Isolation Tool" >> "$evfile"
				fi
			else
				{
				echo "#!/bin/sh"
				echo ""
				echo "$script_xdir/$script_name run-firewall & # ($script_name) Network Isolation Tool" 
				} > "$evfile"
				chmod 0755 "$evfile"
			fi
		;;
		delete)
			
			if [ -f "$evfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$evfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$evfile"
				fi
			fi
		;;
	esac
}

evfile_service_event_end() {
	evfile=$env_file_srv_end

	# Confirm the event files are created. Usage evfile_service_event_end create
	case $1 in
		create)
			
			if [ -f "$evfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$evfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$evfile"
				fi
				
				{
				 echo 'if [ "$1" == "restart" ] && [ "$2" == "wireless" ]; then { '"$script_xdir"'/'"$script_name"' run-config && '"$script_xdir"'/'"$script_name"' run-firewall & }; fi # '"($script_name) Network Isolation Tool"
				 echo 'if { [ "$1" = "start" ] || [ "$1" = "restart" ]; } && [ "$2" = "firewall" ]; then { '"$script_xdir"'/'"$script_name"' run-firewall & }; fi # '"($script_name) Network Isolation Tool"
				} >> "$evfile"
			else
				{
				 echo "#!/bin/sh"
				 echo ""
				 echo 'if [ "$1" == "restart" ] && [ "$2" == "wireless" ]; then { '"$script_xdir"'/'"$script_name"' run-config && '"$script_xdir"'/'"$script_name"' run-firewall & }; fi # '"($script_name) Network Isolation Tool"
				 echo 'if { [ "$1" = "start" ] || [ "$1" = "restart" ]; } && [ "$2" = "firewall" ]; then { '"$script_xdir"'/'"$script_name"' run-firewall & }; fi # '"($script_name) Network Isolation Tool"
				} > "$evfile"
				chmod 0755 $evfile
			fi
		;;
		delete)
			
			if [ -f "$evfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$evfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$evfile"
				fi
			fi
		;;
	esac
}

evfile_services_start() {
	evfile=$env_file_srv_start

	# Confirm the event files are created. Usage evfile_services_start create
	case $1 in
		create)
			
			if [ -f $evfile ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$evfile")
				filelinecountex=$(grep -cx "$script_xdir/$script_name run-config & # ($script_name) Network Isolation Tool" "$evfile")
				
				if [ "$filelinecount" -gt 1 ] || { [ "$filelinecountex" -eq 0 ] && [ "$filelinecount" -gt 0 ]; }; then
					sed -i -e '/# ('"$script_name"')/d' "$evfile"
				fi
				
				if [ "$filelinecountex" -eq 0 ]; then
					echo "$script_xdir/$script_name run-config & # ($script_name) Network Isolation Tool" >> "$evfile"
				fi
			else
				{
				 echo "#!/bin/sh"
				 echo ""
				 echo "$script_xdir/$script_name run-config & # ($script_name) Network Isolation Tool" 
				} > "$evfile"
				chmod 0755 "$evfile"
			fi
		;;
		delete)
			
			if [ -f "$evfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$evfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$evfile"
				fi
			fi
		;;
	esac
}

pcfile_avahi() {
	pcfile=$env_file_avahi_pc

	# Confirm the avahi files are created. Usage pcfile_avahi create
	case $1 in
		create)

			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$pcfile")

				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$pcfile"

					if [ "$(grep -c 'CONFIG' '$pcfile')" -eq 0 ]; then
						{
						echo 'CONFIG=$1'
						echo ''
						} >> "$pcfile"
					fi

					if [ "$(grep -c 'helper.sh' '$pcfile')" -eq 0 ]; then
						{
						echo '. /usr/sbin/helper.sh'
						echo ''
						} >> "$pcfile"
					fi

					{
				 	 echo 'pc_append "[reflector]" "$CONFIG" # ('"$script_name"') Network Isolation Tool'
				 	 echo 'pc_append "enable-reflector=yes" "$CONFIG" # ('"$script_name"') Network Isolation Tool'
					 echo ''
				 	 echo 'pc_append "[Server]" "$CONFIG" # ('"$script_name"') Network Isolation Tool'
				 	 echo 'pc_append "cache-entries-max=0" "$CONFIG" # ('"$script_name"') Network Isolation Tool'
					} >> "$pcfile"

					service restart_mdns >/dev/null 2>&1
				fi

			else
				{
				 echo '#!/bin/sh'
				 echo 'CONFIG=$1'
				 echo ''
				 echo '. /usr/sbin/helper.sh'
				 echo ''
				 echo 'pc_append "[reflector]" "$CONFIG" # ('"$script_name"') Network Isolation Tool'
				 echo 'pc_append "enable-reflector=yes" "$CONFIG" # ('"$script_name"') Network Isolation Tool'
				 echo ''
				 echo 'pc_append "[Server]" "$CONFIG" # ('"$script_name"') Network Isolation Tool'
				 echo 'pc_append "cache-entries-max=0" "$CONFIG" # ('"$script_name"') Network Isolation Tool'
				} > "$pcfile"

				chmod 0755 "$pcfile"
				service restart_mdns >/dev/null 2>&1
			fi
		;;
		delete)

			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c "$script_name" "$pcfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$pcfile"

					service restart_mdns >/dev/null 2>&1
				fi
			fi
		;;
	esac
}

pcfile_cron() {

	# Confirm the cron job is created. Usage pcfile_cron create
	case $1 in
		create)
			filelinecount=$(cru l | grep -c "$script_name")
		
			lc=1
			while [ $lc -le $filelinecount ]; do
				cru d "$script_name.$lc"
				lc=$((lc + 1))
			done

			cru a "$script_name.1" "*/10 * * * * $script_xdir/$script_name check-config"
			cru a "$script_name.2" "0 */12 * * * $script_xdir/$script_name check-update"
		;;
		delete)
			filelinecount=$(cru l | grep -c "$script_name")
			
			lc=1
			while [ $lc -le $filelinecount ]; do
				cru d "$script_name.$lc"
				lc=$((lc + 1))
			done
		;;
	esac
}

pcfile_dnsmasq() {
	pcfile=$env_file_dnsmasq_pc

	# Confirm the dnsmasq files are created. Usage pcfile_dnsmasq create
	case $1 in
		create)
			
			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$pcfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$pcfile"

					if [ "$(grep -c 'CONFIG' '$pcfile')" -eq 0 ]; then
						{
						echo 'CONFIG=$1'
						echo ''
						} >> "$pcfile"
					fi

					if [ "$(grep -c 'helper.sh' '$pcfile')" -eq 0 ]; then
						{
						echo '. /usr/sbin/helper.sh'
						echo ''
						} >> "$pcfile"
					fi
				fi
			else
				{
				 echo '#!/bin/sh'
				 echo 'CONFIG=$1'
				 echo ''
				 echo '. /usr/sbin/helper.sh'
				 echo ''
 				} > "$pcfile"
				chmod 0755 "$pcfile"
			fi
		;;
		delete)
			
			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" $pcfile)
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$pcfile"
				fi
			fi
		;;
	esac
}

pcfile_hosts() {
	pcfile=$env_file_hosts_pc

	# Confirm the hosts files are created. Usage pcfile_hosts create
	case $1 in
		create)
			
			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$pcfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$pcfile"

					if [ "$(grep -c 'CONFIG' '$pcfile')" -eq 0 ]; then
						{
						echo 'CONFIG=$1'
						echo ''
						} >> "$pcfile"
					fi

					if [ "$(grep -c 'helper.sh' '$pcfile')" -eq 0 ]; then
						{
						echo '. /usr/sbin/helper.sh'
						echo ''
						} >> "$pcfile"
					fi
				fi
			else
				{
				 echo '#!/bin/sh'
				 echo 'CONFIG=$1'
				 echo ''
				 echo '. /usr/sbin/helper.sh'
				 echo ''
 				} > "$pcfile"
				chmod 0755 "$pcfile"
			fi
		;;
		delete)
			
			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" $pcfile)
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/# ('"$script_name"')/d' "$pcfile"
				fi
			fi
		;;
	esac
}

dhcp_config() {
	bri_name=$2

	case $1 in
		create)

			# Confirm the function was called with the correct arguments.
			if [ $# -ne 2 ] || ! validate_bridge "$bri_name" ; then
				loggerEx "Error: Invalid arguments. Usage: dhcp_config create br8."
				
				script_lock delete # Unlock script
				exit $env_error # NOK
			fi
			restart_dnsmasq=$env_no_restart

			pcfile=$env_file_dnsmasq_pc
			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$pcfile")

				if [ "$filelinecount" -gt 1 ] || [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/'"$bri_name"'/,/# ('"$script_name"')/d' "$pcfile"
				fi

				# Gathering values from config
				bri_ipaddr=$(getconf_bri_ipaddr "$bri_name")
				bri_netmask=$(getconf_bri_netmask "$bri_name")
				bri_dhcp_start=$(getconf_bri_dhcp_start "$bri_name")
				bri_dhcp_end=$(getconf_bri_dhcp_end "$bri_name")
				bri_staticlist=$(getconf_bri_staticlist "$bri_name")

				loggerEx "Applying DHCPv4 settings for bridge($bri_name)."

				# DHCPv4 interface
				echo 'pc_append "interface='"$bri_name"'" "$CONFIG" # ('"$script_name"') Network Isolation Tool' >> "$pcfile"
				
				# DHCPv4 ip address range
				# DHCPv4 lease time: 86400s (1 day)
				echo 'pc_append "dhcp-range='"$bri_name"','"$bri_dhcp_start"','"$bri_dhcp_end"','"$bri_netmask"',86400s" "$CONFIG" # ('"$script_name"') Network Isolation Tool' >> "$pcfile"
				
				# DHCPv4 default gateway
				echo 'pc_append "dhcp-option='"$bri_name"',3,'"$bri_ipaddr"'" "$CONFIG" # ('"$script_name"') Network Isolation Tool' >> "$pcfile"

				# DHCPv4 ip address reservation
				for static in $(echo "${bri_staticlist#<}" | tr '<' ' '); do

					macaddr=$(echo "$static" | awk -F'[<>]' '{print $1}')
					ipaddr=$(echo "$static" | awk -F'[<>]' '{print $2}')
					dnsaddr=$(echo "$static" | awk -F'[<>]' '{print $3}')
					netname=$(echo "$static" | awk -F'[<>]' '{print $NF}')

					if [ -n "$dnsaddr" ]; then
						echo 'pc_append "dhcp-option=tag:'"$macaddr"',6,'"$dnsaddr"'" "$CONFIG" # '"$bri_name"' # ('"$script_name"') Network Isolation Tool' >> $pcfile
					fi

					if [ -n "$netname" ]; then
						echo 'pc_append "dhcp-host='"$macaddr"',set:'"$macaddr"','"$netname"','"$ipaddr"'" "$CONFIG" # '"$bri_name"' # ('"$script_name"') Network Isolation Tool' >> $pcfile
					else
						echo 'pc_append "dhcp-host='"$macaddr"',set:'"$macaddr"','"$ipaddr"'" "$CONFIG" # '"$bri_name"' # ('"$script_name"') Network Isolation Tool' >> $pcfile
					fi
				done

				# Setup nvram values for bridge.
				nvram set "${bri_name}_dhcp_start"="$bri_dhcp_start"
				nvram set "${bri_name}_dhcp_end"="$bri_dhcp_end"
				nvram set "${bri_name}_staticlist"="$bri_staticlist"
				nvram commit

				loggerEx "DHCPv4 settings for bridge($bri_name) completed."

				unset bri_staticlist
				unset bri_dhcp_end
				unset bri_dhcp_start

				restart_dnsmasq=$env_restart
			fi 

			pcfile=$env_file_hosts_pc
			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c '# '"($script_name) Network Isolation Tool" "$pcfile")

				if [ "$filelinecount" -gt 1 ] || [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/'"$bri_name"'/,/# ('"$script_name"')/d' "$pcfile"
				fi

				# Gathering values from config
				bri_ipaddr=$(getconf_bri_ipaddr "$bri_name")
				bri_staticlist=$(getconf_bri_staticlist "$bri_name")
				lan_domain=$(getconf_lan_domain)
				lan_hostname=$(getconf_lan_hostname)
				lan_fqn_hostname=$(getconf_lan_fqn_hostname)

				loggerEx "Applying Hosts settings for bridge($bri_name)."

				# Hosts definition
				echo 'pc_append "'"$bri_ipaddr"' '"$lan_fqn_hostname"' '"$lan_hostname"'" "$CONFIG" # '"$bri_name"' # ('"$script_name"') Network Isolation Tool' >> "$pcfile"
				echo 'pc_append "'"$bri_ipaddr"' '"$lan_fqn_hostname"'" "$CONFIG" # '"$bri_name"' # ('"$script_name"') Network Isolation Tool' >> "$pcfile"

				for static in $(echo "${bri_staticlist#<}" | tr '<' ' '); do

					ipaddr=$(echo "$static" | awk -F'[<>]' '{print $2}')
					netname=$(echo "$static" | awk -F'[<>]' '{print $NF}')
					if [ -n "$netname" ] && [ -n "$lan_domain" ]; then netname="$netname.$lan_domain"; fi

					if [ -n "$netname" ]; then
						echo 'pc_append "'"$ipaddr"' '"$netname"'" "$CONFIG" # '"$bri_name"' # ('"$script_name"') Network Isolation Tool' >> $pcfile
					fi
				done

				loggerEx "Hosts settings for bridge($bri_name) completed."

				unset lan_fqn_hostname
				unset lan_hostname
				unset bri_staticlist

				restart_dnsmasq=$env_restart
			fi

			if [ "$restart_dnsmasq" -eq "$env_restart" ]; then
				# Restart dnsmasq service
				service restart_dnsmasq >/dev/null 2>&1
			fi
		;;
		delete)

			# Confirm the function was called with the correct arguments.
			if [ $# -ne 2 ] || ! validate_bridge "$bri_name" ; then
				loggerEx "Error: Invalid arguments. Usage: dhcp_config delete br8."
				
				script_lock delete # Unlock script
				exit $env_error # NOK
			fi
			restart_dnsmasq=$env_no_restart

			pcfile=$env_file_dnsmasq_pc
			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c "$script_name" "$pcfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/'"$bri_name"'/,/# ('"$script_name"')/d' "$pcfile"

					# Setup nvram values for bridge.
					nvram unset "${bri_name}_dhcp_end"
					nvram unset "${bri_name}_dhcp_start"
					nvram unset "${bri_name}_staticlist"
					nvram commit

					loggerEx "DHCPv4 settings for bridge($bri_name) removed."

					restart_dnsmasq=$env_restart
				fi
			fi

			pcfile=$env_file_hosts_pc
			if [ -f "$pcfile" ]; then
				filelinecount=$(grep -c "$script_name" "$pcfile")
				
				if [ "$filelinecount" -gt 0 ]; then
					sed -i -e '/'"$bri_name"'/,/# ('"$script_name"')/d' "$pcfile"

					loggerEx "Hosts settings for bridge($bri_name) removed."

					restart_dnsmasq=$env_restart
				fi
			fi

			if [ "$restart_dnsmasq" -eq "$env_restart" ]; then
				# Restart dnsmasq service
				service restart_dnsmasq >/dev/null 2>&1
			fi			
		;;
	esac		

	return 0 # OK
}

bridge_enabled() {

	# Confirm the bridge name is enabled. Usage: bridge_enabled br8
	case "$(nvram get "${1}_enabled")" in
		"0") return 1 ;; # NOK
		"1") return 0 ;; # OK
		*)   return $env_error ;; # NOK
	esac
}

bridge_exists() {

	# Confirm the bridge exists. Usage: bridge_exists br8
	echo "$(gethw_bri_enabled "$1")" | grep -q "$1" > /dev/null 2>&1
	return $? # Return 0 if the bridge is found (success) and other value if the bridge is not found (error)	
}

bridge_ifname_exists() {

	# Confirm the interface exists in the bridge. Usage: bridge_ifname_exists br8 wl0.1
	echo "$(gethw_bri_ifnames "$1")" | grep -q "$2" > /dev/null 2>&1
	return $? # Return 0 if the interface is found (success) and other value if the interface is not found (error)	
}

bridge_config() {
	bri_name=$2

	case $1 in
		create)

			# Confirm the function was called with the correct arguments.
			if [ $# -ne 2 ] || ! validate_bridge "$bri_name" ; then
				loggerEx "Error: Invalid arguments. Usage: bridge_config create br8."
				
				script_lock delete # Unlock script
				exit $env_error # NOK
			fi

			# Confirm the bridge does not exists.
			if ! bridge_exists "$bri_name"; then

				# Gathering values from config
				bri_ipaddr=$(getconf_bri_ipaddr "$bri_name")
				bri_netmask=$(getconf_bri_netmask "$bri_name")

				# Create a network bridge for interface isolation.
				loggerEx "Create a network bridge($bri_name) for interface isolation."
				brctl addbr "$bri_name" >/dev/null 2>&1
				brctl stp "$bri_name" on >/dev/null 2>&1 # STP to prevent bridge loops.

				# Setup the IPv4 address for network bridge.
				# IPv6 link local address will be assigned automatically if enabled.
				loggerEx "Setting up IPv4 address($bri_ipaddr) for bridge($bri_name)."
				ifconfig "$bri_name" "$bri_ipaddr" netmask "$bri_netmask" >/dev/null 2>&1
				ifconfig "$bri_name" allmulti up >/dev/null 2>&1

				# Setup bridge isolation.
				bridge_isolate "$1" "$bri_name" 0

				# Setup nvram values for bridge.
				nvram set "${bri_name}_enabled"=$env_enable
				nvram set "${bri_name}_ipaddr"="$bri_ipaddr"
				nvram set "${bri_name}_netmask"="$bri_netmask"
				nvram commit

				loggerEx "Network bridge($bri_name) created."
			fi

			# Setup DHCPv4 for network bridge.
			dhcp_config "$1" "$bri_name"
		;;
		delete)

			# Confirm the function was called with one argument.
			if [ $# -ne 2 ] || ! validate_bridge "$bri_name" ; then
				loggerEx "Error: Invalid arguments. Usage: bridge_config delete br8."
				
				script_lock delete # Unlock script
				exit $env_error # NOK
			fi

			# Confirm the bridge does exists.
			if bridge_exists "$bri_name"; then
				
				# Remove DHCPv4 for network bridge.
				dhcp_config "$1" "$bri_name"

				# Delete the network bridge.
				ifconfig "$bri_name" down >/dev/null 2>&1
				brctl delbr "$bri_name" >/dev/null 2>&1

				# Remove bridge isolation.
				bridge_isolate "$1" "$bri_name" 0

				# Setup nvram values for bridge.
				nvram unset "${bri_name}_ap_isolate"
				nvram unset "${bri_name}_ifnames"
				nvram unset "${bri_name}_netmask"
				nvram unset "${bri_name}_ipaddr"
				nvram unset "${bri_name}_enabled"
				nvram commit

				loggerEx "Network bridge($bri_name) deleted."
			fi
		;;
	esac		

	return 0 # OK
}

bridge_ifname_change() {
	bri_src=$1
	bri_dst=$2
	if_name=$3

	# Confirm the function was called with three arguments.
	if [ $# -ne 3 ] ; then
		loggerEx "Error: Invalid number of arguments. Usage: bridge_ifname_change br0 br8 wl0.1."
		
		script_lock delete # Unlock script
		exit $env_error # NOK
	fi

	# Remove interface from the source bridge.
	brctl delif "$bri_src" "$if_name" >/dev/null 2>&1
	loggerEx "Interface($if_name) removed from bridge($bri_src)."
	
	# Add interface to destination bridge.
	brctl addif "$bri_dst" "$if_name" >/dev/null 2>&1

	loggerEx "Interface($if_name) added to bridge($bri_dst)."

	return 0 # OK
}

bridge_ifname_config() {
	bri_name=$2

	case $1 in
		create)

			# Confirm the function was called with two arguments.
			if [ $# -ne 2 ] || ! validate_bridge "$bri_name" ; then
				loggerEx "Error: Invalid number of arguments. Usage: bridge_ifname_config create br8."
				
				script_lock delete # Unlock script
				exit $env_error # NOK
			fi

			# Confirm the bridge does exists.
			if bridge_exists "$bri_name"; then

				# Gathering values from config.
				bri_ifnames=$(getconf_bri_ifnames "$bri_name")
				hw_ifnames=$(gethw_bri_ifnames "$bri_name")

				# Gathering if_names to be added to configuration.
				for if_name in $hw_ifnames; do

					bri_ifnames=$(echo "$bri_ifnames" | sed "s/$if_name//;s/  */ /g") # Remove if_names that match
				done

				# Add interfaces to configuration.
				for if_name in $bri_ifnames; do

					bridge_ifname_change br0 "$bri_name" "$if_name"
				done

				# Gathering values from config.
				bri_ifnames=$(getconf_bri_ifnames "$bri_name")
				hw_ifnames=$(gethw_bri_ifnames "$bri_name")

				# Gathering if_names to be removed from configuration
				for if_name in $bri_ifnames; do

					hw_ifnames=$(echo "$hw_ifnames" | sed "s/$if_name//;s/  */ /g") # Remove if_names that match
				done

				# Remove interfaces from configuration.
				for if_name in $hw_ifnames; do

					bridge_ifname_change "$bri_name" br0 "$if_name"
				done

				# Get interfaces from default bridge.
				br0_ifnames=$(gethw_bri_ifnames br0)

				# Setup nvram values for bridge.
				nvram set br0_ifnames="$br0_ifnames"
				nvram set lan_ifnames="$br0_ifnames"
				nvram set "${bri_name}_ifnames"="$bri_ifnames"
				nvram commit
			fi
		;;
		delete)

			# Confirm the function was called with one argument.
			if [ $# -ne 2 ] || ! validate_bridge "$bri_name" ; then
				loggerEx "Error: Invalid arguments. Usage: bridge_ifname_config delete br8."
				
				script_lock delete # Unlock script
				exit $env_error # NOK
			fi

			# Confirm the bridge does exists.
			if bridge_exists "$bri_name"; then

				# Get interfaces from bridge.
				bri_ifnames=$(gethw_bri_ifnames "$bri_name")

				for if_name in $bri_ifnames; do

					bridge_ifname_change "$bri_name" br0 "$if_name"
				done

				# Get interfaces from default bridge.
				br0_ifnames=$(gethw_bri_ifnames br0)

				# Setup nvram values for bridge.
				nvram set br0_ifnames="$br0_ifnames"
				nvram set lan_ifnames="$br0_ifnames"
				nvram unset "${bri_name}_ifnames"
				nvram commit
			fi
		;;
	esac
	
	return 0 # OK
}

bridge_isolate() {
	bri_name=$2
	restart_wireless="$(if [ $# -eq 2 ]; then echo "$env_restart"; else echo "$3"; fi)"

	case $1 in
		create)
			action=$env_enable
		;;
		delete)
			action=$env_disable
		;;
	esac

	# Confirm the function was called with two or three arguments.
	if { [ $# -ne 2 ] && [ $# -ne 3 ]; } || ! validate_bridge "$bri_name" ; then
		loggerEx "Error: Invalid number of arguments. Usage: bridge_isolate create/delete br8."
		
		script_lock delete # Unlock script
		exit $env_error # NOK
	fi

	# Gathering values from config.
	bri_ifnames=$(getconf_bri_ifnames "$bri_name")
	bri_ifnames=$(echo "$bri_ifnames" | grep -o -E "$env_regex_wl_ifname")
	
	# Setup nvram values for bridge.
	for if_name in $bri_ifnames; do

		nvram set "${if_name}_ap_isolate"="$action"

		loggerEx "Set interface($if_name) AP isolated($action)."
	done

	nvram set "${bri_name}_ap_isolate"="$action"
	nvram commit

	if [ "$restart_wireless" -eq "$env_restart" ]; then
		# Restart Wireless service
		service restart_wireless >/dev/null 2>&1
	fi

	return 0 # OK	
}

firewall_config() {
	bri_name=$2

	case $1 in
		create)
			action="-I"
		;;
		delete)
			action="-D"
		;;
	esac

	# Confirm the function was called with the correct arguments.
	if [ $# -ne 2 ] || ! validate_bridge "$bri_name" ; then
		loggerEx "Error: Invalid arguments. Usage: firewall_config create/delete br8."
		
		script_lock delete # Unlock script
		exit 1 # Error
	fi

	# Gathering values from config
	bri_ifnames=$(getconf_bri_ifnames "$bri_name")
	bri_ifnames=$(echo "$bri_ifnames" | grep -o -E "$env_regex_wl_ifname")
	bri_ipaddr=$(getconf_bri_ipaddr "$bri_name")
	bri_netmask=$(getconf_bri_netmask "$bri_name")
	bri_netaddr=$(convert_netaddr "$bri_ipaddr" "$bri_netmask")
	bri_allow_internet=$(getconf_bri_allow_internet "$bri_name")
	bri_allow_onewayaccess=$(getconf_bri_allow_onewayaccess "$bri_name")

	https_lanport="$(nvram get https_lanport)"
	sshd_port="$(nvram get sshd_port)"
	lan_ifname="$(nvram get lan_ifname)"
	wan0_ifname="$(nvram get wan0_ifname)"

	loggerEx "Applying Ethernet Bridge IPv4 BROUTING rules for bridge($bri_name)."

	for if_name in $bri_ifnames; do

		# Remove all ebtables BROUTING rules for each guest interface
		ebrules="$(ebtables -t broute -L | grep "$if_name")"
		echo "$ebrules" | while IFS= read -r ebline; do

			eval "ebtables -t broute -D BROUTING $ebline"
		done
	done

	loggerEx "Applying Packet Filtering IPv4 INPUT, FORWARD and NAT rules for bridge($bri_name)."

	# Remove all iptables INPUT and FORWARD rules for the bridge.
	iprules="$(iptables --list-rules | grep "$bri_name")"
	echo "$iprules" | while IFS= read -r ipline; do

		ipline=$(echo "$ipline" | cut -c 3-) # Remove the first two characters
		eval "iptables -D $ipline"
	done

	# Remove all iptables NAT rules for the bridge.
	iprules="$(iptables -t nat --list-rules | grep "$bri_name")"
	echo "$iprules" | while IFS= read -r ipline; do

		ipline=$(echo "$ipline" | cut -c 3-) # Remove the first two characters
		eval "iptables -t nat -D $ipline"
	done

	# Remove nvram values
	nvram unset "${bri_name}_allow_internet"
	nvram unset "${bri_name}_allow_onewayaccess"
	nvram commit

	if [ $action = "-I" ]; then

		# Provides support for adding comments to rules in iptables
		modprobe xt_comment

		# Allow new incoming connections from bridge.
		iptables "$action" INPUT -i "$bri_name" -m state --state NEW -m comment --comment "($script_name)" -j ACCEPT

		# Allow bridge access to default router services: icmp, dns, dhcp, ntp, mDNS.
		iptables "$action" INPUT -i "$bri_name" -p icmp -m comment --comment "($script_name)" -j ACCEPT
		iptables "$action" INPUT -i "$bri_name" -p tcp -m multiport --dports 53 -m comment --comment "($script_name)" -j ACCEPT
		iptables "$action" INPUT -i "$bri_name" -p udp -m multiport --dports 67,123,5353 -m comment --comment "($script_name)" -j ACCEPT

		# Forbid bridge access to the web UI and SSH of the router.
		iptables "$action" INPUT -i "$bri_name" -p tcp -m multiport --dport "$sshd_port","$https_lanport" -m comment --comment "($script_name)" -j DROP

		# Forbid packets from bridge to be forwarded to other interfaces.
		iptables "$action" FORWARD -i "$bri_name" -m comment --comment "($script_name)" -j DROP

		# Allow packet forwarding inside bridge.
		iptables "$action" FORWARD -i "$bri_name" -o "$bri_name" -m comment --comment "($script_name)" -j ACCEPT

		# Allow packet forwarding between bridge and wan (internet access).
		if [ $bri_allow_internet -eq $env_enable ]; then
			iptables "$action" FORWARD -i "$bri_name" -o "$wan0_ifname" -m comment --comment "($script_name)" -j ACCEPT
		fi

		# Allow one-way traffic from lan to bridge.
		if [ $bri_allow_onewayaccess -eq $env_enable ]; then
			iptables -I FORWARD -i "$lan_ifname" -o "$bri_name" -m comment --comment "($script_name)" -j ACCEPT
			iptables -I FORWARD -i "$bri_name" -o "$lan_ifname" -m state --state RELATED,ESTABLISHED -m comment --comment "($script_name)" -j ACCEPT
		fi

		# Allow multicast address
		iptables "$action" INPUT -i "$bri_name" -d 224.0.0.0/4 -j ACCEPT

		# NAT inside ip address on bridge.
		iptables -t nat "$action" POSTROUTING -s "$bri_netaddr" -d "$bri_netaddr" -o "$bri_name" -m comment --comment "($script_name)" -j MASQUERADE

		# Setup nvram values for bridge
		nvram set "${bri_name}_allow_internet"="$bri_allow_internet"
		nvram set "${bri_name}_allow_onewayaccess"="$bri_allow_onewayaccess"
		nvram commit
	fi

	loggerEx "Applying Ethernet Bridge and Packet Filtering custom scripts for bridge($bri_name)."

	if [ $action = "-I" ]; then

		cfiles=$(find "$script_cdir" -name "$bri_name*iptables.sh" -o -name "$bri_name*ebtables.sh")
		for file in $cfiles; do
			if [ -f "$file" ] && [ -x "$file" ]; then

				loggerEx "Executing custom script: $file."
				sh "$file"
			else 
				loggerEx "Error. The custom script either does not exist or is not executable: $file."
			fi
		done
	fi

	loggerEx "Ethernet Bridge and Packet Filtering setup complete for bridge($bri_name)."

	unset wan0_ifname
	unset lan_ifname
	unset sshd_port
	unset https_lanport

	return 0 # OK
}

wlif_enabled() {

	# Confirm the interface name is enabled. Usage: wlif_enabled wl0.1
	case "$(nvram get "${1}_bss_enabled")" in
		"0") return 1 ;; # NOK
		"1") return 0 ;; # OK
		*)   return $env_error ;; # NOK
	esac
}

wlif_exists() {

	# Confirm the interface name exists. Usage: wlif_exists wl0.1
	echo "$(gethw_if_enabled)" | grep -q $1 > /dev/null 2>&1
	return $? # Return 0 if the interface is found (success) and other value if the interface is not found (error)
}

wlif_lanaccess() {

	# Confirm the interface name has lan access. Usage: wlif_lanaccess wl0.1
	case "$(nvram get "${1}_lanaccess")" in
		"off") return 1 ;; # NOK
		"on")  return 0 ;; # OK
		*)     return $env_error ;; # NOK
	esac
}

wlif_bounceclients() {
	bri_name=$1

	# Confirm the function was called with the correct arguments.
	if [ $# -ne 1 ] || ! validate_bridge "$bri_name" ; then
		loggerEx "Error: Invalid arguments. Usage: wlif_bounceclients br8."
		
		script_lock delete # Unlock script
		exit $env_error # NOK
	fi

	loggerEx "Forcing $script_name Gest Wifi clients on bridge($bri_name) to reauthenticate."

	# Gathering values from config.
	bri_ifnames=$(getconf_bri_ifnames "$bri_name")
	bri_ifnames=$(echo "$bri_ifnames" | grep -o -E "$env_regex_wl_ifname")
	
	for if_name in $bri_ifnames; do
		# Set radio off of bridge interface.
		wl -i "$if_name" radio off >/dev/null 2>&1
	done

	sleep 10

	for if_name in $bri_ifnames; do
		# Set radio on of bridge interface.
		wl -i "$if_name" radio on >/dev/null 2>&1
	done

	# Flush and restart services
	ip -s -s neigh flush all >/dev/null 2>&1
	killall -q networkmap
	sleep 5
	if [ -z "$(pidof networkmap)" ]; then
		networkmap >/dev/null 2>&1 &
	fi

	loggerEx "Reauthentication of Gest wifi clients on bridge($bri_name) complete."

	return 0 # OK
}

wlif_listclients() {
	bri_name=$1

	# Confirm the function was called with the correct arguments.
	if [ $# -ne 1 ] || ! validate_bridge "$bri_name" ; then
		loggerEx "Error: Invalid arguments. Usage: wlif_listclients br8."
		
		exit $env_error # NOK
	fi

	# Gathering values from config.
	bri_ipaddr=$(getconf_bri_ipaddr "$bri_name")
	bri_ifnames=$(getconf_bri_ifnames "$bri_name")
	bri_ifnames=$(echo "$bri_ifnames" | grep -o -E "$env_regex_wl_ifname")
	arpdump="$(arp -i "$bri_name" | grep -v "incomplete")"

	# Checks for clients connected in the bridge.
	if [ -z "$arpdump" ] || [ -z "${arpdump##*No match found*}" ] ; then

		printf "No clients on bridge(%s).\n" $bri_name
		return $env_error # NOK
	fi

	# Cycle through wireless interfaces.
	for if_name in $bri_ifnames; do

		assoclist="$(wl -i "$if_name" assoclist | awk '{print $2}' | xargs)"
		for macaddr in $assoclist; do

			arpinfo="$(arp -a | grep -i "$macaddr")"
			if [ -n "$arpinfo" ]; then

				echo "$arpinfo" | while IFS= read -r arpentry; do

					ipaddr="$(echo "$arpentry" | awk '{print $2}' | sed -e 's/(//g;s/)//g')"
					hostname="$(echo "$arpentry" | awk '{print $1}')"
					if [ $hostname = "?" ]; then hostname="$(nslookup $ipaddr $bri_ipaddr | awk 'END{print $NF}' | xargs)"; fi
					if [ -z "$hostname" ]; then  hostname="Unknown"; fi

					printf "%-15s %-15s %-20s %-20s %-20s\n" $bri_name $if_name $ipaddr $macaddr $hostname
				done
			fi

			# Remove arp entry from arp dump.
			arpdump="$(echo "$arpdump" | grep -i -v "$macaddr")"
		done
	done

	# Reset variables
	unset ipaddr
	unset macaddr
	unset hostname

	# Cycle through the remaining arp entries.
	if [ -n "$arpdump" ]; then

		echo "$arpdump" | while IFS= read -r arpentry; do

			ipaddr="$(echo "$arpentry" | awk '{print $2}' | sed -e 's/(//g;s/)//g')"
			macaddr="$(echo "$arpentry" | awk '{print $4}' | awk '{print toupper($0)}')" 
			hostname="$(echo "$arpentry" | awk '{print $1}')"
			if [ $hostname = "?" ]; then hostname="$(nslookup $ipaddr $bri_ipaddr | awk 'END{print $NF}' | xargs)"; fi
			if [ -z "$hostname" ]; then  hostname="Unknown"; fi

			printf "%-15s %-15s %-20s %-20s %-20s\n" $bri_name "ethernet" $ipaddr $macaddr $hostname
		done
	fi

	return 0 # OK
}

configEx() {

	# Confirm bridges(br3, br4, br8) enabled and delete unnecessary
	if bridge_enabled br3 ; then

		if ! wlif_enabled wl0.2 || wlif_lanaccess wl0.2 ; then

			bridge_ifname_config delete br3
			bridge_config delete br3
		fi
	fi
	if bridge_enabled br4 ; then

		if ! wlif_enabled wl1.2 || wlif_lanaccess wl1.2 ; then

			bridge_ifname_config delete br4
			bridge_config delete br4
		fi
	fi
	if bridge_enabled br8 ; then
	
		if ! wlif_enabled wl0.2 || wlif_lanaccess wl0.2 || ! wlif_enabled wl1.2 || wlif_lanaccess wl1.2 ; then

			bridge_ifname_config delete br8
			bridge_config delete br8
		fi
	fi
	# Confirm bridges(br5, br6, br9) enabled and delete unnecessary
	if bridge_enabled br5 ; then

		if ! wlif_enabled wl0.3 || wlif_lanaccess wl0.3 ; then

			bridge_ifname_config delete br5
			bridge_config delete br5
		fi
	fi
	if bridge_enabled br6 ; then

		if ! wlif_enabled wl1.3 || wlif_lanaccess wl1.3 ; then

			bridge_ifname_config delete br6
			bridge_config delete br6
		fi
	fi
	if bridge_enabled br9 ; then
	
		if ! wlif_enabled wl0.3 || wlif_lanaccess wl0.3 || ! wlif_enabled wl1.3 || wlif_lanaccess wl1.3 ; then

			bridge_ifname_config delete br9
			bridge_config delete br9
		fi
	fi

	# Confirm wireless interfaces(wl0.2, wl1.2) are enabled and with lanacess enabled
	if wlif_enabled wl0.2 && ! wlif_lanaccess wl0.2 ; then

		if ! wlif_enabled wl1.2 || (wlif_enabled wl1.2 && wlif_lanaccess wl1.2) ; then

			if [ "$(getconf_bri_enabled br3)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br3
				bridge_ifname_config create br3
			fi
		fi
	fi
	if wlif_enabled wl1.2 && ! wlif_lanaccess wl1.2 ; then

		if ! wlif_enabled wl0.2 || (wlif_enabled wl0.2 && wlif_lanaccess wl0.2) ; then

			if [ "$(getconf_bri_enabled br4)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br4
				bridge_ifname_config create br4
			fi
		fi
	fi
	if (wlif_enabled wl0.2 && wlif_enabled wl1.2) && (! wlif_lanaccess wl0.2 && ! wlif_lanaccess wl1.2) ; then

		if compare_ssid wl0.2 wl1.2 ; then # The ssids are equal so one bridge

			if [ "$(getconf_bri_enabled br8)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br8
				bridge_ifname_config create br8
			fi
		else # The ssids are not equal so create separated bridges
	
			if [ "$(getconf_bri_enabled br3)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br3
				bridge_ifname_config create br3
			fi
			if [ "$(getconf_bri_enabled br4)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br4
				bridge_ifname_config create br4
			fi
		fi

	fi
	
	# Confirm wireless interfaces(wl0.3, wl1.3) are enabled and with lanacess enabled
	if wlif_enabled wl0.3 && ! wlif_lanaccess wl0.3 ; then

		if ! wlif_enabled wl1.3 || (wlif_enabled wl1.3 && wlif_lanaccess wl1.3) ; then

			if [ "$(getconf_bri_enabled br5)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br5
				bridge_ifname_config create br5
			fi
		fi
	fi
	if wlif_enabled wl1.3 && ! wlif_lanaccess wl1.3 ; then

		if ! wlif_enabled wl0.3 || (wlif_enabled wl0.3 && wlif_lanaccess wl0.3) ; then

			if [ "$(getconf_bri_enabled br6)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br6
				bridge_ifname_config create br6
			fi
		fi
	fi
	if (wlif_enabled wl0.3 && wlif_enabled wl1.3) && (! wlif_lanaccess wl0.3 && ! wlif_lanaccess wl1.3) ; then

		if compare_ssid wl0.3 wl1.3 ; then # The ssids are equal so one bridge

			if [ "$(getconf_bri_enabled br9)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br9
				bridge_ifname_config create br9
			fi
		else # The ssids are not equal so create separated bridges
	
			if [ "$(getconf_bri_enabled br5)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br5
				bridge_ifname_config create br5
			fi
			if [ "$(getconf_bri_enabled br6)" != $env_disable ]; then # Confirm the bridge is enabled

				bridge_config create br6
				bridge_ifname_config create br6
			fi
		fi
	fi
}

device_firmware_version(){
	echo "$1" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'
}

download_file() {
	dwfile=""

	# Donwload files. Usage: download_file file "https://github.com/LICENSE" "LICENSE"
	if [ ! -d "$script_dir" ] ; then
		mkdir -p "$script_dir"
	fi

	case $1 in
		config)
			
			dwfile="$script_config$([ -f $script_config ] && echo ".new")"

			if download_file file "$script_repo/$script_name.conf" "$dwfile"; then
				chmod 0644 "$dwfile"
				dos2unix "$dwfile"
			fi
		;;
		exe|script)

			dwfile="$script_xdir/$script_name"

			if download_file file "$script_repo/$script_name.sh" "$dwfile"; then
				chmod 0755 "$dwfile"
				dos2unix "$dwfile"
			fi
		;;
		README.md|LICENSE)

			dwfile="/tmp/$1"

			if download_file file "$script_repo/$1" "$dwfile"; then

				if ! diff -q "$script_dir/$1" "$dwfile" >/dev/null 2>&1; then
					cp "$dwfile" "$script_dir/$1"
				fi
				rm -f "$dwfile"
			fi
		;;
		file)

			scfile=$2
			dwfile=$3

			# Confirm that the files exists.
			if ! /usr/sbin/curl --head --fail "$scfile" >/dev/null 2>&1 ; then
				loggerEx cli "Error. File does not exist at source URL: $scfile."
				return $env_error # NOK
			fi

			# Download the file.
			if ! /usr/sbin/curl -fsL --retry 3 "$scfile" -o "$dwfile" ; then
				loggerEx cli "Error. Failed to download file: $scfile."
				return $env_error # NOK
			fi
		;;
	esac

	return 0 # OK
}

generate_passphrase() {
	passlength=16

	if validate_number "$1"; then

		if [ "$1" -le 32 ] && [ "$1" -ge 8 ]; then
			passlength="$1"
		else
			loggerEx "Error. Passphrase length is not between 8 and 32, using default of 16 characters."
		fi
	else
		loggerEx "Error. Passphrase length provided is invalid, using default of 16 characters."
	fi
	
	< /dev/urandom tr -cd 'A-Za-z0-9' | head -c "$passlength"
}

script_conditions() {
	finalcheck=$env_disable
	dversion="$(nvram get buildno)"

	# Confirm that all device requirements are meet.
	if [ "$(nvram get sw_mode)" -ne 1 ]; then
		loggerEx cli "Device is not running in router mode - non-router modes are not supported."
		finalcheck=$env_enable
	fi

	if [ "$(nvram get jffs2_scripts)" -ne 1 ]; then
		loggerEx cli "Device doesn't have Custom JFFS Scripts enabled."
		finalcheck=$env_enable
	fi

	if [ "$(device_firmware_version "$dversion")" -lt "$(device_firmware_version 384.5)" ] && [ "$(device_firmware_version "$dversion")" -ne "$(device_firmware_version 374.43)" ]; then
		loggerEx cli "Older Merlin firmware detected - service-event requires 384.5 or later. Please update to the latest version."
		finalcheck=$env_enable
	elif [ "$(device_firmware_version "$dversion")" -eq "$(device_firmware_version 374.43)" ]; then
		loggerEx cli "John's fork detected - service-event requires 374.43_32D6j9527 or later. Please update to the latest version."
		finalcheck=$env_enable
	fi

	return $finalcheck
}

script_check_config() {

	loggerEx cli "Starting configuration check of script($script_name)."
	sleep 1

	# Confirm file exists and has the configuration
	if [ ! -f "$script_md5" ] || [ "$(grep -c '^config' $script_md5)" -eq 0 ] ; then
		loggerEx cli "Configuration checksum not detected for .conf file. Creating one."
		echo "config $(md5sum $script_config | awk '{print $1}')" >> $script_md5
		chmod 0644 $script_md5
	fi 

	# Compare the checksum for config file with the stored value
	svdmd5=$(grep "^config" $script_md5 | awk '{print $2}')
	cfgmd5=$(md5sum $script_config | awk '{print $1}')

	if [ "$svdmd5" != "$cfgmd5" ]; then
		loggerEx cli "Configuration change detected on .config file."

		for bri_name in $(gethw_bri_enabled); do
			script_lock create # Lock script to prevent duplication

			if [ "$(getconf_bri_ifnames "$bri_name" nv)" != "$(getconf_bri_ifnames "$bri_name" sc)" ]; then
				loggerEx cli "Configuration change detected on bridge($bri_name) interfaces. Applying changes."

				# Setting new values in nvram
				nvram set "${bri_name}_ifnames"="$(getconf_bri_ifnames "$bri_name" sc)"
				nvram commit

				bridge_ifname_config create "$bri_name"
			fi

			if [ "$(getconf_bri_dhcp_start "$bri_name" nv)" != "$(getconf_bri_dhcp_start "$bri_name" sc)" ] || [ "$(getconf_bri_dhcp_end "$bri_name" nv)" != "$(getconf_bri_dhcp_end "$bri_name" sc)" ] || [ "$(getconf_bri_staticlist "$bri_name" nv)" != "$(getconf_bri_staticlist "$bri_name" sc)" ]; then
				loggerEx cli "Configuration change detected on bridge($bri_name) DHCPv4 settings. Applying changes."

				# Setting new values in nvram
				nvram set "${bri_name}_dhcp_start"="$(getconf_bri_dhcp_start "$bri_name" sc)"
				nvram set "${bri_name}_dhcp_end"="$(getconf_bri_dhcp_end "$bri_name" sc)"
				nvram set "${bri_name}_staticlist"="$(getconf_bri_staticlist "$bri_name" sc)"
				nvram commit

				dhcp_config create "$bri_name"
			fi

			if [ "$(getconf_bri_allow_internet "$bri_name" nv)" != "$(getconf_bri_allow_internet "$bri_name" sc)" ] || [ "$(getconf_bri_allow_onewayaccess "$bri_name" nv)" != "$(getconf_bri_allow_onewayaccess "$bri_name" sc)" ]; then
				loggerEx cli "Configuration change detected on bridge($bri_name) firewall settings. Applying changes."

				# Setting new values in nvram
				nvram set "${bri_name}_allow_internet"="$(getconf_bri_allow_internet "$bri_name" sc)"
				nvram set "${bri_name}_allow_onewayaccess"="$(getconf_bri_allow_onewayaccess "$bri_name" sc)"
				nvram commit

				firewall_config create "$bri_name"
			fi

			if [ "$(getconf_bri_ap_isolate "$bri_name" nv)" != "$(getconf_bri_ap_isolate "$bri_name" sc)" ]; then
				loggerEx cli "Configuration change detected on bridge($bri_name) isolation. Applying changes."

				case "$(getconf_bri_ap_isolate "$bri_name" sc)" in
					1) bridge_isolate create "$bri_name" ;;
					0) bridge_isolate delete "$bri_name" ;;
				esac
			fi

			# Save checksum for config file
			sed -i "s/^config .*/config $(md5sum $script_config | awk '{print $1}')/" "$script_md5"

			script_lock delete # Unlock script
		done
	fi

	loggerEx cli "Script($script_name) configuration check complete."
}

script_check_update() {

	# Get script versions from local & repo
	localver=$(grep "script_version=" "$script_xdir/$script_name" | grep -m1 -oE "$env_regex_version")
	repover=$(/usr/sbin/curl -fsL --retry 3 "$script_repo/$script_name.sh" | grep "script_version=" | grep -m1 -oE $env_regex_version)

	# Get checksum from local & repo
	localmd5="$(md5sum "$script_xdir/$script_name" | awk '{print $1}')"
	repomd5="$(curl -fsL --retry 3 "$script_repo/$script_name.sh" | md5sum | awk '{print $1}')"

	if [ -z $repover ] || [ -z $repomd5 ]; then

		loggerEx cli "Online repository unavailable for update check."
		return 0 # NOK	
	fi 

	if [ "$localver" != "$repover" ] || [ "$localmd5" != "$repomd5" ]; then
		
		loggerEx cli "New version of script($script_name $repover) available."
		return 1 # Update
	fi

	return 0 # OK
}

script_diagnostics() {

	clear
	printf "Diagnostics procedure will collect the information listed below, and store them in an encrypted file with a unique random passphrase.\\n"
	printf " - list of settings in device memory (nvram)\\n"
	printf " - list of ethernet bridges (brctl)\\n"
	printf " - list of network interfaces (ifconfig)\\n"
	printf " - list of ip routing tabble (ip route)\\n"
	printf " - list of packet filtering and NAT rules (iptables)\\n"
	printf " - list of ethernet bridge frame rules (ebtables)\\n"
	printf " - %s configuration file (%s)\\n" $script_name $script_config
	printf " - %s log file (%s)\\n" $script_name $log_file
	printf " - customized configuration files:\\n"
	printf "  . services-start (%s)\\n" $env_file_srv_start
	printf "  . service_event_end (%s)\\n" $env_file_srv_end
	printf "  . firewall-start (%s)\\n" $env_file_fw_start
	printf "  . avahi (%s)\\n" $env_file_avahi_pc	
	printf "  . dnsmasq (%s)\\n" $env_file_dnsmasq_pc
	printf "  . hosts (%s)\\n" $env_file_hosts_pc
	printf "\\n"
	while true; do
		printf "Do you want to continue? (y/n): "
		read -r key
		case "$key" in
			y|Y) break    ;;
			n|N) return 1 ;;
			*)
				printf "\\nPlease choose a valid option.\\n\\n"
			;;
		esac
	done

	printf "Generating %s diagnostics...\\n\\n" "$script_name"

	# Create script directory	
	if [ ! -d "$script_diag" ] ; then
		mkdir -p "$script_diag"
	fi

	# List of settings in device memory
	nvram show | grep -E "\<$env_regex_bridge" > "$script_diag/nvram.txt"

	# List of ethernet bridges
	brctl show > "$script_diag/brctl.txt"

	# List of network interfaces
	ifconfig -a > "$script_diag/ifconfig.txt"

	ip route show > "$script_diag/iproute.txt"
	echo "" >> "$script_diag/iproute.txt"
	ip route show table all >> "$script_diag/iproute.txt"

	# List of packet filtering and NAT rules
	iptables-save > "$script_diag/iptables.txt"

	# List of ethernet bridge frame rules
	ebtables -L > "$script_diag/ebtables.txt"
	echo "" >> "$script_diag/ebtables.txt"
	ebtables -t broute -L >> "$script_diag/ebtables.txt"

	# Configuration file
	cp "$script_config" "$script_diag/$script_name.conf"

	# Log file
	cp "$log_file" "$script_diag/$script_name.log"

	# Customized configuration files
	cp "$env_file_srv_start" "$script_diag/services-start.txt"
	cp "$env_file_srv_end" "$script_diag/service_event_end.txt"
	cp "$env_file_fw_start" "$script_diag/firewall-start.txt"
	cp "$env_file_avahi_pc" "$script_diag/avahi_pc.txt"
	cp "$env_file_dnsmasq_pc" "$script_diag/dnsmasq_pc.txt"	
	cp "$env_file_hosts_pc" "$script_diag/hosts_pc.txt"	

	# Compress and protect diagnostics files
	passphrase="$(generate_passphrase 32)"
	tar -czf "/tmp/$script_name.tar.gz" -C "$script_diag" .
	/usr/sbin/openssl enc -aes-256-cbc -k "$passphrase" -e -in "/tmp/$script_name.tar.gz" -out "/tmp/$script_name.tar.gz.enc"
	
	loggerEx cli "Diagnostics saved to /tmp/$script_name.tar.gz.enc with passphrase: $passphrase"
	pause

	# Remove diagnostics files
	rm -f "/tmp/$script_name.tar.gz" 2>/dev/null
	rm -rf "$script_diag" 2>/dev/null
	
	unset passphrase
}

script_install () {

	loggerEx clio "Starting installation of script($script_name $script_version)."
	sleep 1

	loggerEx clio "Checking if the device requirements are met for script($script_name $script_version)."

	if ! script_conditions ; then
		loggerEx clio "Requirements for script($script_name $script_version) not met, please check the device logs."
		script_lock delete # Unlock script
		pause

		exit 1
	fi

	evfile_services_start create 2>/dev/null
	evfile_service_event_end create 2>/dev/null
	evfile_firewall_start create 2>/dev/null
	pcfile_avahi create 2>/dev/null
	pcfile_dnsmasq create 2>/dev/null
	pcfile_hosts create 2>/dev/null
	pcfile_cron create 2>/dev/null

	# Create script directory	
	if [ ! -d "$script_dir" ] ; then
		mkdir -p "$script_dir"
	fi
	# Create custom scripts directory
	if [ ! -d "$script_cdir" ] ; then
		mkdir -p "$script_cdir"
	fi

	# Donwload files from repository
	download_file config
	download_file README.md
	download_file LICENSE

	loggerEx clio "Script($script_name $script_version) installation complete."
	while true; do
		printf "Do you want to run config? (y/n): "
		read -r key
		case "$key" in
			y|Y)
				script_lock delete # Unlock script
				
				sh "$script_xdir/$script_name" run-config

				loggerEx clio "Configuration complete."
				break
			;;
			n|N)
				break
			;;
			*)
				printf "\\nPlease choose a valid option.\\n\\n"
			;;
		esac
	done
}

script_lock() {
	lkfile="/tmp/$script_name.lock"

	# Confirm script is already in execution to prevent duplication. Usage: script_lock create
	case $1 in
		create)
			
			if [ -f "$lkfile" ]; then

				lkage=$(($(date +%s) - $(date +%s -r "$lkfile")))
				if [ "$lkage" -gt 600 ]; then
					loggerEx "Error. Stale lock file found (>600 seconds old). Purging lock."
					kill "$(sed -n '1p' $lkfile)" >/dev/null 2>&1
					rm -f "$lkfile" 2>/dev/null
					
					echo "$$" > "$lkfile"
					return 0 # OK
				else
					loggerEx "Error. Lock file found (age: $lkage seconds). Stopping to prevent duplication."
					if [ $# -eq 1 ] || [ -z "$2" ]; then
						exit $env_error # NOK
					else
						return $env_error # NOK
					fi
				fi
			else

				echo "$$" > "$lkfile"
				return 0 # OK
			fi
		;;
		delete)

			rm -f "$lkfile" 2>/dev/null
			return 0 # OK
		;;
	esac
}

script_update() {

	loggerEx cli "Starting script($script_name $script_version) update check."
	sleep 1

	if ! script_check_update ; then
		while true; do
			printf "Do you want to update? (y/n): "
			read -r key
			case "$key" in
				y|Y)
					script_lock create # Lock script to prevent duplication

					dwfile="$script_xdir/$script_name"

					download_file file "$script_repo/$script_name.sh" "$dwfile"
					chmod 0755 "$dwfile"
					dos2unix "$dwfile"

					script_lock delete # Unlock script
					
					loggerEx cli "Update script($script_name) complete. Starting install procedure."

					sh "$dwfile" install
					break
				;;
				n|N) 
					break 
				;;
				*) 
					printf "\\nPlease choose a valid option.\\n\\n"
				;;
			esac
		done
	else
		loggerEx cli "The script($script_name $script_version) version is updated."
	fi
}

script_uninstall() {

	loggerEx clio "Starting script($script_name $script_version) uninstall."
	sleep 1

	for bri_name in $(gethw_bri_enabled); do
		
		firewall_config delete "$bri_name"
		bridge_config delete "$bri_name"
		bridge_ifname_config delete "$bri_name"
	done

	# Remove script directory and files
	rm -rf "$script_dir"

	pcfile_cron delete 2>/dev/null
	pcfile_hosts delete 2>/dev/null
	pcfile_dnsmasq delete 2>/dev/null
	pcfile_avahi delete 2>/dev/null
	evfile_firewall_start delete 2>/dev/null
	evfile_service_event_end delete 2>/dev/null
	evfile_services_start delete 2>/dev/null

    # Remove script file
	rm -f "$script_xdir/$script_name" 2>/dev/null

	loggerEx clio "Script($script_name $script_version) uninstall complete."
}

show_about() {
	cat <<EOF
About
  $script_name is a feature expansion for AsusWRT-Merlin that automatically creates 
  separated subnets from lan network, based on the active guest network and settings.
License
  $script_name is free to use under the GNU General Public License
  version 3 (GPL-3.0) https://opensource.org/licenses/GPL-3.0
Help & Support
  
Source code
  https://github.com/janico82/$script_name
EOF
	printf "\\n"
}

show_help() {
	cat <<EOF
Available commands: \\n"
  $script_name about              explains $script_name functionality
  $script_name install            installs script
  $script_name uninstall          uninstalls script
  $script_name update             apply $script_name updates
  $script_name run-config         apply $script_name configuration
  $script_name run-firewall       apply $script_name firewall configuration
  $script_name run-diagnostics    checks the health of $script_name
  $script_name check-config       checks the $script_name configuration file for changes and re-apply
  $script_name check-update       checks for new updates
  $script_name bounce-clients     restart guest interfaces radios
  $script_name list-clients	      show a list of connected client
EOF
	printf "\\n"
}

show_banner() {
	clear
	printf "\\n"
	printf "#############################################################\\n"
	printf "##            _           __  __           _ _             ##\\n"
	printf "##        ___| |__  _ __ |  \/  | ___ _ __| (_)_ __        ##\\n"
	printf "##       / __| '_ \| '_ \| |\/| |/ _ \ '__| | | '_ \       ##\\n"
	printf "##       \__ \ |_) | | | | |  | |  __/ |  | | | | | |      ##\\n"
	printf "##       |___/_.__/|_| |_|_|  |_|\___|_|  |_|_|_| |_|      ##\\n"
	printf "##                                                         ##\\n"
	printf "##          https://github.com/janico82/sbnMerlin          ##\\n"
	printf "##                                                         ##\\n"
	printf "#############################################################\\n"
	printf "\\n"
}

show_menu() {
	printf "  %s Main menu - version: %s \\n" "$script_name" "$script_version"
	printf "  1.   Edit configuration \\n"
	printf "  2.   Run configuration \\n"
	printf "  d.   Run diagnostics \\n"
	printf "  u.   Update check \\n"
	printf "  e.   Exit \\n"
	printf "  z.   Uninstall \\n"
	printf "\\n"
	printf "#############################################################\\n"
	printf "\\n"

	while true; do
		printf "Choose an option: "
		read -r key
		case $key in
			1)
				vi "$script_config"
				
				while true; do
					printf "\\nDo you want to apply %s configuration changes? (y/n): " "$script_name"
					read -r conf
					case "$conf" in
						y|Y) script_check_config ;;
						n|N) break ;;
						*) 
							printf "\\nPlease choose a valid option.\\n\\n"
						;;
					esac
				done
			;;
			2)
				show_banner
				script_lock create # Lock script to prevent duplication
				
				configEx
				
				script_lock delete # Unlock script
			;;
			d)
				show_banner
				script_diagnostics
			;;
			u)
				show_banner
				script_update
			;;
			e)
				show_banner
				printf "\\nThanks for using %s!\\n\\n" "$script_name"
				exit 0
			;;
			z)
				show_banner
				while true; do
					printf "\\nAre you sure you want to uninstall %s? (y/n): " "$script_name"
					read -r conf
					case "$conf" in
						y|Y) 
							script_lock create # Lock script to prevent duplication

							script_uninstall 

							script_lock delete # Unlock script
							exit 0
						;;
						n|N) break ;;
						*) 
							printf "\\nPlease choose a valid option.\\n\\n"
						;;
					esac
				done
			;;
			*)
				printf "\\nPlease choose a valid option.\\n\\n"
			;;
		esac
	done

	show_banner
	show_menu
}

pause() {

	read -rp "Press any key to continue..."
	return 0
}

#############################################################################################

# Confirm the script was called with no arguments
if [ $# -eq 0 ] || [ -z "$1" ]; then

	show_banner
	show_menu
	exit 0
fi

# Run script argument commands
case "$1" in
	bc|bounce-clients)
		script_lock create # Lock script to prevent duplication

		# Cycle from every allowed bridges and force Guest clients to reauthenticate. 
		for bri_name in $(gethw_bri_enabled); do
			
			wlif_bounceclients "$bri_name"
		done

		script_lock delete # Unlock script
		exit 0	
	;;
	cc|check-config)

		# Check script configuration changes.
		script_check_config

		exit 0
	;;
	cu|check-update)

		# Check for script update.
		script_check_update

		exit 0
	;;
	install)
		script_lock create # Lock script to prevent duplication
		
		# Execute the script install instructions.
		script_install

		script_lock delete # Unlock script
		exit 0
	;;
	lc|list-clients)

		# Cycle from every allowed bridges, print header and list Guest clients. 
		printf "%-15s %-15s %-20s %-20s %-20s\n" "bridge name" "interfaces" "client IP address" "client MAC address" "client name"
		for bri_name in $(gethw_bri_enabled); do
			
			wlif_listclients "$bri_name"
		done

		exit 0	
	;;
	rc|run-config)

		# OnDeviceReboot create the cron jobs
		pcfile_cron create 2>/dev/null

		script_lock create # Lock script to prevent duplication

		# Execute the bridge config logic function.
		configEx

		script_lock delete # Unlock script
		exit 0
	;;
	rd|run-diagnostics)

		# Execute the scripts diagnostic instructions.
		script_diagnostics

		exit 0
	;;
	rf|run-firewall)
		script_lock create # Lock script to prevent duplication

		# Cycle from every allowed bridges and apply firewall rules for the enabled ones. 
		for bri_name in $(gethw_bri_enabled); do
			
			firewall_config create "$bri_name"
		done

		script_lock delete # Unlock script
		exit 0
	;;
	u|update)

		# Execute the script update instructions.
		script_update

		exit 0
	;;
	uninstall)
		script_lock create # Lock script to prevent duplication

		# Execute the script removal instructions.
		script_uninstall

		script_lock delete # Unlock script
		exit 0
	;;
	about)

		show_banner
		show_about
		exit 0
	;;
	help)
		show_banner
		show_help
		exit 0
	;;
	*)
		printf "Error: Invalid script arguments"
		exit $env_error
	;;
esac