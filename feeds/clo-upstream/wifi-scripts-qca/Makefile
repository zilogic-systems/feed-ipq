#
# Copyright (C) 2024 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wifi-scripts-qca
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

PKG_MAINTAINER:=Felix Fietkau <nbd@nbd.name>

PKG_BUILD_DIR:=$(BUILD_DIR)/wifi-scripts-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/wifi-scripts-qca
  SECTION:=utils
  CATEGORY:=Base system
  DEPENDS:=+netifd +ucode +ucode-mod-nl80211 +ucode-mod-rtnl +ucode-mod-ubus +ucode-mod-uci
  TITLE:=Wi-Fi configuration scripts
  PKGARCH:=all
endef

define Package/wifi-scripts-qca/description
 A set of scripts that handle setup and configuration of Wi-Fi devices.
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

EXTERNAL_FILE_DIR:=./files-qca-mac80211
FILE_DIR_HOSTAPD:=./files-qca-hostapd

define Package/wifi-scripts-qca/install
	$(INSTALL_DIR) $(1)
	$(CP) ./files/* $(1)/

	# Recipe extension for package : wifi-scripts.mk
	$(INSTALL_DATA) $(EXTERNAL_FILE_DIR)/files/lib/wifi/mac80211.sh $(1)/lib/wifi
	$(INSTALL_BIN)  $(EXTERNAL_FILE_DIR)/files/lib/netifd-wlan/wireless/mac80211.sh $(1)/lib/netifd/wireless/
	$(INSTALL_DATA) $(FILE_DIR_HOSTAPD)/files/hostapd.sh $(1)/lib/netifd/hostapd.sh
endef

$(eval $(call BuildPackage,wifi-scripts-qca))
