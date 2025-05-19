include $(TOPDIR)/rules.mk

PKG_NAME:=board-cfg-ipq95xx
PKG_RELEASE:=1
PKG_VERSION:=1.0

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=board-cfg-ipq95xx
  CATEGORY:=ipq-ext
  TITLE:=board-cfg-ipq95xx
  DEPENDS:=@TARGET_ipq95xx
endef

define Package/$(PKG_NAME)/description
  This package contains board configuration details like Boot, DDR and Flash layout for IPQ based target boards
endef

Build/Compile=true

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)/
	$(CP) -rf ./files/board-cfg-ipq9574 $(STAGING_DIR_IMAGE)/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
