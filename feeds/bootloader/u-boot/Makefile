include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/version.mk

PKG_NAME:=u-boot
PKG_RELEASE:=2023.04

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/boot/u-boot.git
PKG_SOURCE_PROTO:=git
PKG_MIRROR_HASH:=skip
PKG_VERSION:=a258badb1d4e3cf7936046d49cb88bd20e66aa09

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_VERSION:=$(PKG_VERSION)

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_RELEASE)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)
CONFIG_NAME=$(shell echo $(BUILD_VARIANT) | sed 's/.*-//')
DEBUG_NAME=$(shell echo $(BUILD_VARIANT) | sed 's/-.*//')
LOCAL_VARIANT=$(patsubst ipq9574_%,%,\
	$(patsubst ipq5332_%,%,\
	$(patsubst ipq5424_%,%,\
	$(BUILD_VARIANT) \
	)))

UBOOT_STAGING_DIR_IMAGE:=$(STAGING_DIR_IMAGE)/u-boot

include $(INCLUDE_DIR)/package.mk


ifeq ($(CONFIG_LINUX_6_1),y)
KCPPFLAGS += \
	-Wno-error=maybe-uninitialized \
	-Wno-error=address-of-packed-member \
	-Wno-error=attributes \
	-Wno-error=misleading-indentation
endif

define Build/Configure/debug
	echo "CONFIG_SKIP_RESET=y" >> $(PKG_BUILD_DIR)/configs/$(CONFIG_NAME)_defconfig;
endef

EXTERNAL_PATCH_DIR:=$(CURDIR)

define Build/Prepare
	$(call Build/Prepare/Default)

ifeq ($(CONFIG_TARGET_BUILD_PRPL),y)
	$(call PatchDir,$(PKG_BUILD_DIR),$(EXTERNAL_PATCH_DIR)/patches-prpl,)
endif

endef

define Build/Configure
	$(call Build/Configure/$(DEBUG_NAME))
	$(MAKE) -C $(PKG_BUILD_DIR) $(CONFIG_NAME)_defconfig CROSS_COMPILE=$(TARGET_CROSS) TARGETCC=$(TARGET_CC);
endef

define Build/Compile
	VERSION_CODE='$(VERSION_NICK) $(VERSION_NUMBER)' \
	REVISION='$(REVISION)' \
	KBUILD_VERBOSE=1 $(MAKE) -C $(PKG_BUILD_DIR) HOSTSTRIP=true CROSS_COMPILE=$(TARGET_CROSS) \
		TARGETCC=$(TARGET_CC) \
		KCPPFLAGS="$(KCPPFLAGS)" \
		KCFLAGS=-Werror \
		HOSTLDFLAGS="$(HOST_LDFLAGS) -pthread -Werror" \
		HOSTCFLAGS="$(HOST_CFLAGS)" \
		DTC=${LINUX_DIR}/scripts/dtc/dtc \
		all
endef

OBJCOPY:=$(TARGET_CROSS)objcopy

define Package/uboot-ipq5332-debug/common
  define Package/uboot-ipq5332-debug-$(1)
    SECTION:=boot
    CATEGORY:=Boot Loaders
    DEPENDS:=@TARGET_ipq53xx
    TITLE:=U-boot for IPQ5322 $(1)
    URL:=http://www.denx.de/wiki/U-Boot
    VARIANT:=debug-ipq5332_$(1)
  endef
endef

define Package/uboot-ipq5332-debug
  $(call Package/uboot-ipq5332-debug/common,$(1),$(2))

  define Package/uboot-ipq5332-debug-$(1)/install
	$(INSTALL_DIR) $(UBOOT_STAGING_DIR_IMAGE)
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot $(PKG_BUILD_DIR)/u-boot-dtb
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot-dtb --set-section-flags .dtb=CONTENTS,ALLOC,DATA --update-section .dtb=$(PKG_BUILD_DIR)/fit-dtb.blob.lzo
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5332-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5332-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(STRIP) $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5332-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot.bin $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5332-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.img
  endef

  $$(eval $$(call BuildPackage,uboot-ipq5332-debug-$(1)))
endef

define Package/uboot-ipq5332/common
  define Package/uboot-ipq5332-$(1)
    SECTION:=boot
    CATEGORY:=Boot Loaders
    DEPENDS:=@TARGET_ipq53xx
    TITLE:=U-boot for IPQ5322 $(1)
    URL:=http://www.denx.de/wiki/U-Boot
    VARIANT:=ipq5332_$(1)
  endef
endef

define Package/uboot-ipq5332
  $(call Package/uboot-ipq5332/common,$(1),$(2))

  define Package/uboot-ipq5332-$(1)/install
	$(INSTALL_DIR) $(UBOOT_STAGING_DIR_IMAGE)
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot $(PKG_BUILD_DIR)/u-boot-dtb
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot-dtb --set-section-flags .dtb=CONTENTS,ALLOC,DATA --update-section .dtb=$(PKG_BUILD_DIR)/fit-dtb.blob.lzo
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5332-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5332-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(STRIP) $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5332-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot.bin $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5332-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.img
  endef

  $$(eval $$(call BuildPackage,uboot-ipq5332-$(1)))
endef

define Package/uboot-ipq9574-debug/common
  define Package/uboot-ipq9574-debug-$(1)
    SECTION:=boot
    CATEGORY:=Boot Loaders
    DEPENDS:=@TARGET_ipq95xx
    TITLE:=U-boot for IPQ9574 $(1)
    URL:=http://www.denx.de/wiki/U-Boot
    VARIANT:=debug-ipq9574_$(1)
  endef
endef

define Package/uboot-ipq9574-debug
  $(call Package/uboot-ipq9574-debug/common,$(1),$(2))

  define Package/uboot-ipq9574-debug-$(1)/install
	$(INSTALL_DIR) $(UBOOT_STAGING_DIR_IMAGE)
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot $(PKG_BUILD_DIR)/u-boot-dtb
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot-dtb --set-section-flags .dtb=CONTENTS,ALLOC,DATA --update-section .dtb=$(PKG_BUILD_DIR)/fit-dtb.blob.lzo
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq9574-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq9574-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(STRIP) $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq9574-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot.bin $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq9574-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.img
  endef

  $$(eval $$(call BuildPackage,uboot-ipq9574-debug-$(1)))
endef

define Package/uboot-ipq9574/common
  define Package/uboot-ipq9574-$(1)
    SECTION:=boot
    CATEGORY:=Boot Loaders
    DEPENDS:=@TARGET_ipq95xx
    TITLE:=U-boot for IPQ9574 $(1)
    URL:=http://www.denx.de/wiki/U-Boot
    VARIANT:=ipq9574_$(1)
  endef
endef

define Package/uboot-ipq9574
  $(call Package/uboot-ipq9574/common,$(1),$(2))

  define Package/uboot-ipq9574-$(1)/install
	$(INSTALL_DIR) $(UBOOT_STAGING_DIR_IMAGE)
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot $(PKG_BUILD_DIR)/u-boot-dtb
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot-dtb --set-section-flags .dtb=CONTENTS,ALLOC,DATA --update-section .dtb=$(PKG_BUILD_DIR)/fit-dtb.blob.lzo
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq9574-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq9574-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(STRIP) $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq9574-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot.bin $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq9574-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.img
  endef

  $$(eval $$(call BuildPackage,uboot-ipq9574-$(1)))
endef

define Package/uboot-ipq5424-debug/common
  define Package/uboot-ipq5424-debug-$(1)
    SECTION:=boot
    CATEGORY:=Boot Loaders
    DEPENDS:=@TARGET_ipq54xx
    TITLE:=U-boot for IPQ5424 $(1)
    URL:=http://www.denx.de/wiki/U-Boot
    VARIANT:=debug-ipq5424_$(1)
  endef
endef

define Package/uboot-ipq5424-debug
  $(call Package/uboot-ipq5424-debug/common,$(1),$(2))

  define Package/uboot-ipq5424-debug-$(1)/install
	$(INSTALL_DIR) $(UBOOT_STAGING_DIR_IMAGE)
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot $(PKG_BUILD_DIR)/u-boot-dtb
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot-dtb --set-section-flags .dtb=CONTENTS,ALLOC,DATA --update-section .dtb=$(PKG_BUILD_DIR)/fit-dtb.blob.lzo
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5424-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5424-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(STRIP) $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5424-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot.bin $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5424-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.img
  endef

  $$(eval $$(call BuildPackage,uboot-ipq5424-debug-$(1)))
endef

define Package/uboot-ipq5424/common
  define Package/uboot-ipq5424-$(1)
    SECTION:=boot
    CATEGORY:=Boot Loaders
    DEPENDS:=@TARGET_ipq54xx
    TITLE:=U-boot for IPQ5424 $(1)
    URL:=http://www.denx.de/wiki/U-Boot
    VARIANT:=ipq5424_$(1)
  endef
endef

define Package/uboot-ipq5424
  $(call Package/uboot-ipq5424/common,$(1),$(2))

  define Package/uboot-ipq5424-$(1)/install
	$(INSTALL_DIR) $(UBOOT_STAGING_DIR_IMAGE)
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot $(PKG_BUILD_DIR)/u-boot-dtb
	$(OBJCOPY) $(PKG_BUILD_DIR)/u-boot-dtb --set-section-flags .dtb=CONTENTS,ALLOC,DATA --update-section .dtb=$(PKG_BUILD_DIR)/fit-dtb.blob.lzo
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5424-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot-dtb $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5424-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(STRIP) $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5424-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot-stripped.elf
	$(CP) $(PKG_BUILD_DIR)/u-boot.bin $(UBOOT_STAGING_DIR_IMAGE)/openwrt-ipq5424-$(SUBTARGET)-$(LOCAL_VARIANT)-u-boot.img
  endef

  $$(eval $$(call BuildPackage,uboot-ipq5424-$(1)))
endef


$(eval $(call Package/uboot-ipq5332,mmc))
$(eval $(call Package/uboot-ipq5332,mmc32))
$(eval $(call Package/uboot-ipq5332,nand))
$(eval $(call Package/uboot-ipq5332,nand32))
$(eval $(call Package/uboot-ipq5332,norplusnand))
$(eval $(call Package/uboot-ipq5332,norplusnand32))
$(eval $(call Package/uboot-ipq5332,norplusmmc))
$(eval $(call Package/uboot-ipq5332,norplusmmc32))
$(eval $(call Package/uboot-ipq5332,tiny_nand32))
$(eval $(call Package/uboot-ipq5332,tiny_v2_nand32))
$(eval $(call Package/uboot-ipq5332,tiny_nand32_64M))
$(eval $(call Package/uboot-ipq5332,tiny_v2_nand32_64M))
$(eval $(call Package/uboot-ipq5332,tiny_nor32))
$(eval $(call Package/uboot-ipq5332,tiny_norplusnand32))
$(eval $(call Package/uboot-ipq5332,tiny_v2_norplusnand32))
$(eval $(call Package/uboot-ipq5332-debug,mmc))
$(eval $(call Package/uboot-ipq5332-debug,mmc32))
$(eval $(call Package/uboot-ipq5332-debug,nand))
$(eval $(call Package/uboot-ipq5332-debug,nand32))
$(eval $(call Package/uboot-ipq5332-debug,norplusnand))
$(eval $(call Package/uboot-ipq5332-debug,norplusnand32))
$(eval $(call Package/uboot-ipq5332-debug,norplusmmc))
$(eval $(call Package/uboot-ipq5332-debug,norplusmmc32))
$(eval $(call Package/uboot-ipq5332-debug,tiny_nand32))
$(eval $(call Package/uboot-ipq5332-debug,tiny_v2_nand32))
$(eval $(call Package/uboot-ipq5332-debug,tiny_nand32_64M))
$(eval $(call Package/uboot-ipq5332-debug,tiny_v2_nand32_64M))
$(eval $(call Package/uboot-ipq5332-debug,tiny_nor32))
$(eval $(call Package/uboot-ipq5332-debug,tiny_norplusnand32))
$(eval $(call Package/uboot-ipq5332-debug,tiny_v2_norplusnand32))

$(eval $(call Package/uboot-ipq9574,mmc))
$(eval $(call Package/uboot-ipq9574,mmc32))
$(eval $(call Package/uboot-ipq9574,nand))
$(eval $(call Package/uboot-ipq9574,nand32))
$(eval $(call Package/uboot-ipq9574,norplusnand))
$(eval $(call Package/uboot-ipq9574,norplusnand32))
$(eval $(call Package/uboot-ipq9574,norplusmmc))
$(eval $(call Package/uboot-ipq9574,norplusmmc32))
$(eval $(call Package/uboot-ipq9574-debug,mmc))
$(eval $(call Package/uboot-ipq9574-debug,mmc32))
$(eval $(call Package/uboot-ipq9574-debug,nand))
$(eval $(call Package/uboot-ipq9574-debug,nand32))
$(eval $(call Package/uboot-ipq9574-debug,norplusnand))
$(eval $(call Package/uboot-ipq9574-debug,norplusnand32))
$(eval $(call Package/uboot-ipq9574-debug,norplusmmc))
$(eval $(call Package/uboot-ipq9574-debug,norplusmmc32))

$(eval $(call Package/uboot-ipq5424,mmc))
$(eval $(call Package/uboot-ipq5424,mmc32))
$(eval $(call Package/uboot-ipq5424,nand))
$(eval $(call Package/uboot-ipq5424,nand32))
$(eval $(call Package/uboot-ipq5424,norplusnand))
$(eval $(call Package/uboot-ipq5424,norplusnand32))
$(eval $(call Package/uboot-ipq5424,norplusmmc))
$(eval $(call Package/uboot-ipq5424,norplusmmc32))
$(eval $(call Package/uboot-ipq5424,tiny_nand32))
$(eval $(call Package/uboot-ipq5424,tiny_norplusnand32))
$(eval $(call Package/uboot-ipq5424-debug,mmc))
$(eval $(call Package/uboot-ipq5424-debug,mmc32))
$(eval $(call Package/uboot-ipq5424-debug,nand))
$(eval $(call Package/uboot-ipq5424-debug,nand32))
$(eval $(call Package/uboot-ipq5424-debug,norplusnand))
$(eval $(call Package/uboot-ipq5424-debug,norplusnand32))
$(eval $(call Package/uboot-ipq5424-debug,norplusmmc))
$(eval $(call Package/uboot-ipq5424-debug,norplusmmc32))
$(eval $(call Package/uboot-ipq5424-debug,tiny_nand32))
$(eval $(call Package/uboot-ipq5424-debug,tiny_norplusnand32))
