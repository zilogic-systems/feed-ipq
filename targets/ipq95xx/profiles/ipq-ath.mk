NSS_COMMON:= kmod-qca-nss-dp-qca

NSS_PPE:= kmod-qca-nss-ppe \
	kmod-qca-nss-ppe-vp \
	kmod-qca-nss-ppe-bridge-mgr \
	kmod-qca-nss-ppe-vlan-mgr \
	kmod-qca-nss-ppe-ds

NSS_CLIENTS_STANDARD:= kmod-qca-ovsmgr

SWITCH_SSDK_NOHNAT_PKGS:= kmod-qca-ssdk-qca-nohnat qca-ssdk-shell swconfig kmod-qca8k

QCA_PHY_PKGS:= kmod-qca81xx kmod-qca8084 kmod-aqr-phy kmod-qca8xxx-phc

NETWORKING:= kmod-bonding

WIFI_OPEN_PKGS:= kmod-ath12k-qca wpad-qca-mesh-openssl \
	hostapd-qca-utils wpa-qca-cli \
	qca-wifi-scripts ath-wifi-scripts wififw_mount_script \
	kmod-telemetry-agent iwinfo

TEST_TOOLS:= ethtool tcpdump

STORAGE:= kmod-usb-storage \
	kmod-usb-storage-extras kmod-usb-storage-uas \
	kmod-fs-vfat losetup

IPQ_ATH_PROFILE_PACKAGES := \
		$(NSS_PPE) $(NSS_CLIENTS_STANDARD) \
		$(NSS_COMMON) $(SWITCH_SSDK_NOHNAT_PKGS) \
		$(QCA_PHY_PKGS) $(NETWORKING) \
		$(WIFI_OPEN_PKGS) \
		$(TEST_TOOLS) $(STORAGE)
