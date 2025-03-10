#!/bin/sh
#Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
#
#Permission to use, copy, modify, and/or distribute this software for any
#purpose with or without fee is hereby granted, provided that the above
#copyright notice and this permission notice appear in all copies.
#
#THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

[ -e /lib/functions.sh ] && . /lib/functions.sh

ifname=$1
CMD=$2
CONFIG=$3
shift
shift
SSID=$@
PASS=$@

i=0
get_section() {
	local config=$1
	local ifname
	local band="${2:4:1}"
	local index=0
	local device

	config_get ifname "$config" ifname
	if [ -n "$ifname" ]; then
		[ "${ifname}" = "$2" ] && eval "$3=$config"
	else
		[ -z "${2:6:1}" ] && index=0 || index="${2:6:1}"
		config_get device "$config" device
		[ "$band" = "${device:11:1}" ]  && [ "${index}" = "$i" ] && eval "$3=$config"
		if [ "$band" = "${device:11:1}" ]
		then
			i=$((i+1))
		fi
	fi
}

hex2string()
{
	I=0
	while [ $I -lt ${#1} ];
	do
		echo -en "\x""${1:$I:2}"
		let "I += 2"
	done
}

get_config_val() {
	local key=$1
	local conf=/var/run/wpa_supplicant-$ifname.conf

	config_val=$(wpa_cli -i"$ifname" get_network 0 "$1" | cut -f 2 -d= | sed -e 's/^"\(.*\)"/\1/')
	if [ "$key" == 'psk' ]; then
		config_val=$(awk "BEGIN{FS=\"=\"} /[[:space:]]${key}=/ {print \$0}" "$conf" |grep "${key}=" |tail -n 1 | cut -f 2 -d= | sed -e 's/^"\(.*\)"/\1/')
	fi
	if [ "$config_val" == "FAIL" ]; then
		config_val=''
	fi
}

update_wireless() {
	get_config_val 'ssid'
	ssid=${config_val}

	get_config_val 'key_mgmt'
	key_mgmt=${config_val}

	get_config_val 'dpp_connector'
	dpp_connector=${config_val}

	get_config_val 'psk'
	psk=${config_val}

	get_config_val 'dpp_csign'
	dpp_csign=${config_val}

	get_config_val 'dpp_pp_key'
	dpp_pp_key=${config_val}

	get_config_val 'dpp_netaccesskey'
	dpp_netaccesskey=${config_val}

	. /sbin/wifi config

	sect=
	config_foreach get_section wifi-iface "$ifname" sect
	uci set wireless.${sect}.ssid=$ssid
	uci set wireless.${sect}.dpp_connector=$dpp_connector
	uci set wireless.${sect}.key=$psk
	uci set wireless.${sect}.dpp_csign=$dpp_csign
	uci set wireless.${sect}.dpp_pp_key=$dpp_pp_key
	uci set wireless.${sect}.dpp_netaccesskey=$dpp_netaccesskey
	uci commit wireless
}

case "$CMD" in
	DPP-CONF-RECEIVED)
		wpa_cli -i"$ifname" remove_network all
		wpa_cli -i"$ifname" add_network
		wpa_cli -i"$ifname" set_network 0 pairwise "CCMP"
		wpa_cli -i"$ifname" set_network 0 group "CCMP"
		wpa_cli -i"$ifname" set_network 0 proto "RSN"
		;;
	DPP-CONFOBJ-AKM)
		encryption=
		dpp=
		sae_require_mfp=
		ieee80211w=
		key_mgmt=
		case "$CONFIG" in
			dpp+psk+sae|dpp-psk-sae)
				key_mgmt="DPP SAE WPA-PSK"
				encryption="sae-mixed"
				dpp=1
				ieee80211w=1
				sae_require_mfp=1
				;;
			dpp+sae|dpp-sae)
				key_mgmt="DPP SAE"
				encryption="sae"
				ieee80211w=2
				dpp=1
				;;
			dpp)
				key_mgmt="DPP"
				encryption="dpp"
				ieee80211w=2
				dpp=1
				;;
			sae)
				key_mgmt="SAE"
				encryption="sae"
				ieee80211w=2
				dpp=0
				;;
			psk+sae|psk-sae)
				key_mgmt="SAE WPA-PSK"
				encryption="sae-mixed"
				ieee80211w=1
				sae_require_mfp=1
				dpp=0
				;;
			psk)
				key_mgmt="WPA-PSK"
				encryption="psk2"
				ieee80211w=1
				dpp=0
				;;
		esac
		wpa_cli -i"$ifname"  set_network 0 ieee80211w "$ieee80211w"
		wpa_cli -i"$ifname"  set_network 0 key_mgmt "$key_mgmt"

		. /sbin/wifi config
		sect=
		config_foreach get_section wifi-iface "$ifname" sect
		uci set wireless.${sect}.encryption=$encryption
		uci set wireless.${sect}.sae_require_mfp=$sae_require_mfp
		uci set wireless.${sect}.dpp=$dpp
		uci set wireless.${sect}.ieee80211w=$ieee80211w
		uci commit wireless
		;;
	DPP-CONFOBJ-SSID)
		wpa_cli -i"$ifname"  set_network 0 ssid \""$SSID"\"
		;;
	DPP-CONNECTOR)
		wpa_cli -i"$ifname" set dpp_connector "$CONFIG"
		wpa_cli -i"$ifname" set_network 0 dpp_connector \""${CONFIG}"\"
		;;
	DPP-CONFOBJ-PASS)
		PASS_STR=$(hex2string "$PASS")

		wpa_cli -i"$ifname" set_network 0 psk \""${PASS_STR}"\"
		wpa_cli -i"$ifname" set_network 0 pairwise "CCMP"
		wpa_cli -i"$ifname" dpp_bootstrap_remove \*
		;;
	DPP-CONFOBJ-PSK)
		PASS_STR=$(hex2string "$CONFIG")
		get_pairwise

		wpa_cli -i"$ifname" set_network 0 psk "$PASS_STR"
		wpa_cli -i"$ifname" set_network 0 pairwise "CCMP"
		wpa_cli -i"$ifname" dpp_bootstrap_remove \*
		;;
	DPP-C-SIGN-KEY)
		wpa_cli -i"$ifname" set dpp_csign "$CONFIG"
		wpa_cli -i"$ifname" set_network 0 dpp_csign "$CONFIG"
		;;
        DPP-CONNECTOR-C-SIGN-KEY)
                wpa_cli -i"$ifname" set dpp_connector_csign "$CONFIG"
		wpa_cli -i"$ifname" set_network 0 dpp_connector_csign "$CONFIG"
                ;;
        DPP-PP-KEY)
                wpa_cli -i"$ifname" set dpp_pp_key "$CONFIG"
		wpa_cli -i"$ifname" set_network 0 dpp_pp_key "$CONFIG"
                ;;
	DPP-PP-KEY)
		wpa_cli -i"$ifname" set dpp_pp_key "$CONFIG"
		wpa_cli -i"$ifname" set_network 0 dpp_pp_key "$CONFIG"
		;;
	DPP-NET-ACCESS-KEY)
		wpa_cli -i"$ifname" set dpp_netaccesskey "$CONFIG"
		wpa_cli -i"$ifname" set_network 0 dpp_netaccesskey "$CONFIG"

		wpa_cli -i"$ifname" enable_network 0
		wpa_cli -i"$ifname" save_config

		wpa_cli -i"$ifname" disable
		wpa_cli -i"$ifname" enable

		update_wireless

		;;
esac
