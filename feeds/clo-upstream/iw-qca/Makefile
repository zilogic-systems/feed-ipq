#
# Copyright (C) 2007-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=iw-qca
PKG_VERSION:=6.9
PKG_RELEASE:=1

PKG_SOURCE:=iw-$(PKG_VERSION).tar.xz
PKG_SOURCE_URL:=@KERNEL/software/network/iw
PKG_HASH:=3f2db22ad41c675242b98ae3942dbf3112548c60a42ff739210f2de4e98e4894

PKG_MAINTAINER:=Felix Fietkau <nbd@nbd.name>
PKG_LICENSE:=GPL-2.0
PKG_CPE_ID:=cpe:/a:kernel:iw

PKG_BUILD_FLAGS:=gc-sections lto

PKG_BUILD_DIR:=$(BUILD_DIR)/iw-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/iw-qca
  SECTION:=net
  CATEGORY:=Network
  TITLE:=cfg80211 interface configuration utility
  URL:=http://wireless.kernel.org/en/users/Documentation/iw
  DEPENDS:= +libnl-tiny
  VARIANT:=tiny
endef

define Package/iw-qca-full
  $(Package/iw-qca)
  TITLE += (full version)
  VARIANT:=full
  PROVIDES:=iw
endef

EXTERNAL_PATCH_DIR:=$(CURDIR)

define Build/Patch
	$(if $(QUILT),rm -rf $(PKG_BUILD_DIR)/patches; mkdir -p $(PKG_BUILD_DIR)/patches)
	$(call PatchDir,$(PKG_BUILD_DIR),$(EXTERNAL_PATCH_DIR)/patches,)
	$(call PatchDir,$(PKG_BUILD_DIR),$(EXTERNAL_PATCH_DIR)/patches-qca,)
	$(if $(QUILT),touch $(PKG_BUILD_DIR)/.quilt_used)
endef

define Build/Configure
	echo "const char iw_version[] = \"$(PKG_VERSION)\";" > $(PKG_BUILD_DIR)/version.c
	echo "#!/bin/sh" > $(PKG_BUILD_DIR)/version.sh
	chmod +x $(PKG_BUILD_DIR)/version.sh
endef

TARGET_CPPFLAGS:= \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	$(TARGET_CPPFLAGS) \
	-DCONFIG_LIBNL20 \
	-D_GNU_SOURCE

ifeq ($(BUILD_VARIANT),full)
  TARGET_CPPFLAGS += -DIW_FULL
  MAKE_FLAGS += IW_FULL=1
endif

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
	LDFLAGS="$(TARGET_LDFLAGS)" \
	NL1FOUND="" NL2FOUND=Y \
	NLLIBNAME="libnl-tiny" \
	LIBS="-lm -lnl-tiny" \
	V=1

define Package/iw-qca/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iw $(1)/usr/sbin/
endef

Package/iw-qca-full/install=$(Package/iw-qca/install)

$(eval $(call BuildPackage,iw-qca))
$(eval $(call BuildPackage,iw-qca-full))
