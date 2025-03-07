include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-nss-ppe
PKG_RELEASE:=2

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/lklm/nss-ppe
PKG_SOURCE_PROTO:=git
PKG_BRANCH:=win.nss.1.0.r24
PKG_MIRROR_HASH:=skip
PKG_VERSION:=3d4eecf57560b6c02ce1567ab5995d4a24b42ab5

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

ifeq ($(CONFIG_TARGET_ipq),y)
subtarget:=$(SUBTARGET)
else
subtarget:=$(CONFIG_TARGET_BOARD)
endif

define KernelPackage/qca-nss-ppe
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for PPE (core driver)
  DEPENDS:=@TARGET_ipq95xx||TARGET_ipq53xx||TARGET_ipq54xx \
		+kmod-qca-ssdk-qca-nohnat \
		+!(TARGET_ipq53xx_ipq53xx_32_QSDK_256||TARGET_ipq54xx_ipq54xx_32_QSDK_256):kmod-nat46-qca
  FILES:=$(PKG_BUILD_DIR)/drv/ppe_drv/qca-nss-ppe.ko
  AUTOLOAD:=$(call AutoLoad,31,qca-nss-ppe)
endef

define KernelPackage/qca-nss-ppe/Description
Kernel module for PPE core driver
endef

define KernelPackage/qca-nss-ppe/install
        $(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/ppe_flow_dump $(1)/usr/bin/
	$(INSTALL_BIN) ./files/ppe_if_map $(1)/usr/bin/
	$(INSTALL_BIN) ./files/nss_perf_config.sh $(1)/lib/
endef

define Build/InstallDev/qca-nss-ppe
	$(INSTALL_DIR) $(1)/usr/include/qca-nss-ppe
	$(CP) $(PKG_BUILD_DIR)/exports/* $(1)/usr/include/qca-nss-ppe/
	$(CP) $(PKG_BUILD_DIR)/drv/exports/* $(1)/usr/include/qca-nss-ppe/
endef

define Build/InstallDev
	$(call Build/InstallDev/qca-nss-ppe,$(1))
endef

EXTRA_CFLAGS+= \
	-I$(STAGING_DIR)/usr/include/qca-ssdk \
	-I$(STAGING_DIR)/usr/include/qca-ssdk/fal \
	-I$(STAGING_DIR)/usr/include/qca-ssdk/init \
	-I$(STAGING_DIR)/usr/include/nat46 \

MAKE_OPTS+=ppe-drv=y

ifeq ($(CONFIG_LOWMEM_FLASH),y)
MAKE_OPTS+=PPE_16M_PROFILE=y
endif

ifeq ($(CONFIG_KERNEL_IPQ_MEM_PROFILE),256)
MAKE_OPTS+=PPE_256M_PROFILE=y
endif

ifneq ($(CONFIG_KERNEL_IPQ_MEM_PROFILE),256)
ifneq ($(CONFIG_LOWMEM_FLASH),y)
MAKE_OPTS+=PPE_IPSEC_ENABLE=y
MAKE_OPTS+=PPE_TUN_ENABLE=y
endif
endif

ifeq ($(CONFIG_TARGET_ipq95xx_generic_QSDK_MinEnt), y)
EXTRA_CFLAGS+= -DPPE_V4_BAD_LEN_EXCEP_DIS
endif

define Build/Compile
	$(KERNEL_MAKE) $(strip $(MAKE_OPTS)) \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		SoC="$(subtarget)" \
		modules
endef

$(eval $(call KernelPackage,qca-nss-ppe))
