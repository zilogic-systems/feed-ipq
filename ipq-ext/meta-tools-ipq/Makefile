include $(TOPDIR)/rules.mk

PKG_NAME:=meta-tools-ipq
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/system/tools/meta.git
PKG_SOURCE_PROTO:=git
PKG_MIRROR_HASH:=skip
PKG_VERSION:=3fb1222d9b725222d16e33a751aaed4a0eca1d2b

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_VERSION:=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=meta-tools
  CATEGORY:=ipq-ext
  TITLE:=meta-tools-ipq
  DEPENDS:=@TARGET_ipq95xx||TARGET_ipq53xx||TARGET_ipq54xx
endef

define Package/$(PKG_NAME)/description
  This package contains required scripts to generate single image for ipq targets
endef

Build/Compile=true

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)/meta-tools
	$(CP) -rf $(PKG_BUILD_DIR)/* $(STAGING_DIR_IMAGE)/meta-tools
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
