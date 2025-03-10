include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-ovsmgr
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/lklm/qca-ovsmgr
PKG_SOURCE_PROTO:=git
PKG_BRANCH:=win.nss.1.0.r24
PKG_MIRROR_HASH:=skip
PKG_VERSION:=6c1fafc4fbdc28474d2199fa2bef6e10c89d2118

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

ifeq ($(CONFIG_TARGET_ipq),y)
subtarget:=$(SUBTARGET)
else
subtarget:=$(CONFIG_TARGET_BOARD)
endif

define KernelPackage/qca-ovsmgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS OpenVSwitch manager
  DEPENDS:=+kmod-openvswitch @!LINUX_3_18 \
	  @TARGET_ipq_ipq807x||TARGET_ipq_ipq807x_64||TARGET_ipq807x||TARGET_ipq807x_64||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64||TARGET_ipq60xx||TARGET_ipq60xx_64||TARGET_ipq_ipq806x||TARGET_ipq_ipq50xx||TARGET_ipq_ipq50xx_64||TARGET_ipq50xx||TARGET_ipq95xx||TARGET_ipq95xx_32||TARGET_ipq53xx||TARGET_ipq54xx
  FILES:=$(PKG_BUILD_DIR)/qca-ovsmgr.ko
  AUTOLOAD:=$(call AutoLoad,50,qca-ovsmgr)
endef

define KernelPackage/qca-ovsmgr/Description
Kernel module for NSS OpenVSwitch manager
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/qca-ovsmgr
	$(CP) $(PKG_BUILD_DIR)/exports/ovsmgr.h $(1)/usr/include/qca-ovsmgr/
endef

EXTRA_CFLAGS += -I$(LINUX_DIR)/net/openvswitch -I$(PKG_BUILD_DIR)/exports

define Build/Compile
	$(KERNEL_MAKE) $(strip $(MAKE_OPTS)) \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		SoC="$(subtarget)" \
		modules
endef

$(eval $(call KernelPackage,qca-ovsmgr))
