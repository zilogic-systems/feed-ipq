include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-ssdk-shell
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/ssdk-shell
PKG_SOURCE_PROTO:=git
PKG_BRANCH:=win.nss.1.0.r24
PKG_MIRROR_HASH:=skip
PKG_VERSION:=36de0b076ead75c47356f4c2397814788883be02

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/qca-ssdk-shell
  SECTION:=QCA
  CATEGORY:=Utilities
  TITLE:=Shell application for QCA SSDK
endef


define Package/qca-ssdk-shell/Description
  This package contains a qca-ssdk shell application for QCA chipset
endef

ifndef CONFIG_TOOLCHAIN_BIN_PATH
CONFIG_TOOLCHAIN_BIN_PATH=$(TOOLCHAIN_DIR)/bin
endif

QCASSDK_CONFIG_OPTS+= TOOL_PATH=$(CONFIG_TOOLCHAIN_BIN_PATH) \
                SYS_PATH=$(LINUX_DIR) \
                TOOLPREFIX=$(TARGET_CROSS) \
                KVER=$(LINUX_VERSION) \
                CFLAGS="$(TARGET_CFLAGS)" \
                LDFLAGS="$(TARGET_LDFLAGS)" \
                ARCH=$(LINUX_KARCH)

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(strip $(QCASSDK_CONFIG_OPTS))
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/qca-ssdk-shell
	$(INSTALL_DIR) $(1)/usr/include/qca-ssdk-shell/sal

	$(CP) -rf $(PKG_BUILD_DIR)/include/fal $(1)/usr/include/qca-ssdk-shell
	$(CP) -rf $(PKG_BUILD_DIR)/include/ref $(1)/usr/include/qca-ssdk-shell
	$(CP) -rf $(PKG_BUILD_DIR)/include/sal/os $(1)/usr/include/qca-ssdk-shell/sal
	$(CP) -rf $(PKG_BUILD_DIR)/include/common $(1)/usr/include/qca-ssdk-shell
	$(CP) -rf $(PKG_BUILD_DIR)/include/common/*.h $(1)/usr/include/qca-ssdk-shell
	$(CP) -rf $(PKG_BUILD_DIR)/include/fal/*.h $(1)/usr/include/qca-ssdk-shell
	$(CP) -rf $(PKG_BUILD_DIR)/include/sal/os/*.h $(1)/usr/include/qca-ssdk-shell
	$(CP) -rf $(PKG_BUILD_DIR)/include/sal/os/linux_user/*.h $(1)/usr/include/qca-ssdk-shell

	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/bin/libssdk_us.so $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/bin/libssdk_us_um.a $(1)/usr/lib/
endef

define Package/qca-ssdk-shell/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/bin/ssdk_sh $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/bin/libssdk_us.so $(1)/usr/lib/
endef


$(eval $(call BuildPackage,qca-ssdk-shell))
